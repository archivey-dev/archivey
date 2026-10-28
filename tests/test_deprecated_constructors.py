"""Building ``ArchiveStream`` or ``MemberPass`` directly still works until 0.4.0, with a
``DeprecationWarning`` that names where to get one instead (DR-12a)."""

from __future__ import annotations

import gzip
import io
import warnings
import zipfile

import pytest

from archivey import ArchiveStream, MemberPass, open_archive, open_stream


def test_archive_stream_constructor_warns_and_still_reads() -> None:
    with pytest.warns(DeprecationWarning, match=r"ArchiveReader\.open\(\)"):
        stream = ArchiveStream(
            lambda: io.BytesIO(b"payload"), translate=lambda _e: None
        )
    with stream:
        assert stream.read() == b"payload"


def test_member_pass_constructor_warns_and_still_iterates() -> None:
    def items():
        yield 1
        yield 2

    with pytest.warns(DeprecationWarning, match=r"stream_members\(\)"):
        members = MemberPass(items())
    assert list(members) == [1, 2]


def test_readers_build_streams_and_passes_without_warning(tmp_path) -> None:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", b"payload")
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        with open_archive(path) as reader:
            assert reader.read("a.txt") == b"payload"
            with reader.stream_members() as members:
                for _member, stream in members:
                    assert stream is not None and stream.read() == b"payload"
            assert [m.name for m in reader] == ["a.txt"]
        gz = tmp_path / "a.gz"
        gz.write_bytes(gzip.compress(b"payload"))
        with open_stream(gz) as stream:
            assert stream.read() == b"payload"
