"""``open_archive(pipe=True)``: the one mode that reads a source that cannot seek.

Pipe mode is a single forward read whatever the source can do, so a seekable source
under ``pipe=True`` gives what a pipe carrying the same bytes gives, and a source that
cannot seek is refused in every other mode.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

import archivey
from archivey import (
    ArchiveyUsageError,
    StreamCapability,
    StreamNotSeekableError,
)
from tests.conftest import unrar_reads_from_pipes
from tests.iso_minimal import minimal_iso
from tests.streams_util import NonSeekableBytesIO

FIXTURE_7Z = (
    Path(__file__).parent / "fixtures" / "damaged_member" / "7z_copy_nonsolid.7z"
)
SPANNED_ZIP = Path(__file__).parent / "fixtures" / "external" / "zip_spanned_infozip"
RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"


def _zip_with_symlink() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "hello")
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, "a.txt")
        mode = zipfile.ZipInfo("run.sh")
        mode.create_system = 3
        mode.external_attr = (stat.S_IFREG | 0o755) << 16
        zf.writestr(mode, "#!/bin/sh\n")
    return buf.getvalue()


def _tar_gz() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in (("one.txt", b"1" * 100), ("two.txt", b"2" * 200)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _first_pass(reader: archivey.ForwardArchiveReader) -> list[tuple]:
    """What a pass yields, as each member looks when it is yielded."""
    seen = []
    for member, stream in reader.stream_members():
        seen.append(
            (
                member.name,
                member.type,
                member.mode,
                member.member_state_final,
                stream.read() if stream is not None else None,
            )
        )
    return seen


def _final(reader: archivey.ForwardArchiveReader) -> list[tuple]:
    return [(m.name, m.type, m.mode) for m in reader.members_report().members]


# --- refusal without pipe=True -------------------------------------------------------


@pytest.mark.parametrize("streaming", [False, True])
def test_a_source_that_cannot_seek_needs_pipe_in_every_mode(streaming: bool) -> None:
    with pytest.raises(StreamNotSeekableError) as info:
        archivey.open_archive(NonSeekableBytesIO(_tar_gz()), streaming=streaming)
    message = str(info.value)
    assert "pipe=True" in message
    assert "streaming=True" not in message


def test_the_refusal_is_the_same_in_both_modes() -> None:
    messages = set()
    for streaming in (False, True):
        with pytest.raises(StreamNotSeekableError) as info:
            archivey.open_archive(NonSeekableBytesIO(_tar_gz()), streaming=streaming)
        messages.add(str(info.value))
    assert len(messages) == 1


def test_a_raw_stream_that_does_not_override_seekable_needs_pipe() -> None:
    # ``io.RawIOBase.seekable()`` answers False unless a subclass says otherwise.
    class ReadOnly(io.RawIOBase):
        def __init__(self, data: bytes) -> None:
            super().__init__()
            self._inner = io.BytesIO(data)

        def readable(self) -> bool:
            return True

        def readinto(self, b) -> int:  # type: ignore[override]  # test double; broad buffer type
            return self._inner.readinto(b)

    with pytest.raises(StreamNotSeekableError):
        archivey.open_archive(ReadOnly(_tar_gz()), streaming=True)
    with archivey.open_archive(ReadOnly(_tar_gz()), pipe=True) as reader:
        assert [m.name for m, _ in reader.stream_members()] == ["one.txt", "two.txt"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs os.mkfifo")
def test_a_fifo_path_needs_pipe(tmp_path: Path) -> None:
    import threading

    fifo = tmp_path / "in.fifo"
    os.mkfifo(fifo)
    data = _tar_gz()

    def feed() -> None:
        with open(fifo, "wb") as out:
            out.write(data)

    for kwargs, ok in (({"streaming": True}, False), ({"pipe": True}, True)):
        writer = threading.Thread(target=feed)
        writer.start()
        try:
            if ok:
                with archivey.open_archive(fifo, **kwargs) as reader:
                    names = [m.name for m, _ in reader.stream_members()]
                assert names == ["one.txt", "two.txt"]
            else:
                # The archive is smaller than a pipe's buffer, so the writer finishes
                # whatever the refused open read.
                with pytest.raises(StreamNotSeekableError):
                    archivey.open_archive(fifo, **kwargs)
        finally:
            writer.join(timeout=10)


def test_a_stream_members_stream_needs_pipe_for_a_nested_archive() -> None:
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as zf:
        zf.writestr("inner.tar.gz", _tar_gz())
    with archivey.open_archive(io.BytesIO(outer.getvalue()), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            with pytest.raises(StreamNotSeekableError):
                archivey.open_archive(stream, streaming=True, parent=reader)
    with archivey.open_archive(io.BytesIO(outer.getvalue()), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            with archivey.open_archive(stream, pipe=True, parent=reader) as inner:
                assert [m.name for m, _ in inner.stream_members()] == [
                    "one.txt",
                    "two.txt",
                ]


# --- pipe=True reads every source as a pipe ------------------------------------------


@pytest.mark.parametrize("kind", ["bytesio", "path", "file"])
def test_pipe_on_a_seekable_source_gives_what_a_pipe_gives(
    kind: str, tmp_path: Path
) -> None:
    data = _zip_with_symlink()
    with archivey.open_archive(NonSeekableBytesIO(data), pipe=True) as reader:
        expected_pass = _first_pass(reader)
        expected_final = _final(reader)
        assert reader.cost.stream_capability is StreamCapability.FORWARD_ONLY

    path = tmp_path / "a.zip"
    path.write_bytes(data)
    if kind == "bytesio":
        source: object = io.BytesIO(data)
    elif kind == "path":
        source = path
    else:
        source = open(path, "rb")  # noqa: SIM115  # closed below
    try:
        with archivey.open_archive(source, pipe=True) as reader:  # type: ignore[call-overload]  # source kinds vary
            assert reader.cost.stream_capability is StreamCapability.FORWARD_ONLY
            assert _first_pass(reader) == expected_pass
            assert _final(reader) == expected_final
    finally:
        if kind == "file":
            source.close()  # type: ignore[attr-defined]  # an open file here


def test_pipe_mode_zip_members_are_not_final_when_yielded() -> None:
    # The difference pipe=True opts into: a ZIP's symlink and modes come from its index.
    data = _zip_with_symlink()
    with archivey.open_archive(io.BytesIO(data), pipe=True) as reader:
        first = _first_pass(reader)
        final = _final(reader)
    assert [entry[3] for entry in first] == [False, False, False]
    assert ("link", archivey.MemberType.SYMLINK, 0o777) in [
        (n, t, m & 0o777 if m is not None else None) for n, t, m in final
    ]
    # From the index: the mode is known when the member is yielded, and the pipe's
    # local header does not carry it.
    modes = {name: mode for name, _t, mode, _f, _d in first}
    assert modes["run.sh"] is None
    with archivey.open_archive(io.BytesIO(data), streaming=True) as reader:
        modes = {name: mode for name, _t, mode, _f, _d in _first_pass(reader)}
    assert modes["run.sh"] is not None
    assert modes["run.sh"] & 0o777 == 0o755


def test_pipe_starts_at_the_stream_position() -> None:
    data = _tar_gz()
    source = io.BytesIO(b"x" * 37 + data)
    source.seek(37)
    with archivey.open_archive(source, pipe=True) as reader:
        assert [m.name for m, _ in reader.stream_members()] == ["one.txt", "two.txt"]


def test_pipe_does_not_close_a_caller_stream() -> None:
    source = io.BytesIO(_tar_gz())
    with archivey.open_archive(source, pipe=True) as reader:
        list(reader.stream_members())
    assert not source.closed


def test_pipe_extracts(tmp_path: Path) -> None:
    with archivey.open_archive(io.BytesIO(_zip_with_symlink()), pipe=True) as reader:
        reader.extract_all(tmp_path / "out")
    assert (tmp_path / "out" / "a.txt").read_bytes() == b"hello"


def test_pipe_ignores_streaming_false() -> None:
    with archivey.open_archive(
        io.BytesIO(_tar_gz()), streaming=False, pipe=True
    ) as reader:
        with pytest.raises(ArchiveyUsageError):
            reader.members()  # type: ignore[attr-defined]  # a forward reader at type level
        assert [m.name for m, _ in reader.stream_members()] == ["one.txt", "two.txt"]


# --- what pipe=True refuses ----------------------------------------------------------


def test_pipe_with_concurrent_operations_is_refused() -> None:
    with pytest.raises(ArchiveyUsageError, match="pipe=True"):
        archivey.open_archive(
            io.BytesIO(_tar_gz()), pipe=True, concurrent_operations=True
        )


def test_pipe_on_a_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "f.txt").write_text("x")
    with pytest.raises(ArchiveyUsageError, match="directory"):
        archivey.open_archive(tmp_path, pipe=True)


def test_pipe_must_be_a_bool() -> None:
    with pytest.raises(ArchiveyUsageError):
        archivey.open_archive(io.BytesIO(_tar_gz()), pipe=1)  # type: ignore[call-overload]  # wrong type on purpose


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda: FIXTURE_7Z.read_bytes(), id="7z"),
        pytest.param(minimal_iso, id="iso"),
    ],
)
def test_a_format_that_needs_seek_is_refused_under_pipe(make) -> None:
    data = make()
    with pytest.raises(
        StreamNotSeekableError, match="cannot be read as a pipe"
    ) as info:
        archivey.open_archive(io.BytesIO(data), pipe=True)
    assert "without pipe=True" in str(info.value)
    # The same bytes from a source that cannot seek: one message for every mode, and it
    # does not propose pipe=True, which could not work either.
    for kwargs in ({}, {"streaming": True}, {"pipe": True}):
        with pytest.raises(StreamNotSeekableError) as info:
            archivey.open_archive(NonSeekableBytesIO(data), **kwargs)  # type: ignore[call-overload]  # kwargs vary
        assert "Pass pipe=True" not in str(info.value)
    # Without the flag, the seekable source reads as usual.
    with archivey.open_archive(io.BytesIO(data)) as reader:
        assert reader.members()


def _split_zip(tmp_path: Path) -> Path:
    """A stdlib ZIP cut in two numbered parts, ``s.zip.001`` and ``s.zip.002``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", "a" * 1000)
        zf.writestr("b.txt", "b" * 1000)
    data = buf.getvalue()
    half = len(data) // 2
    (tmp_path / "s.zip.001").write_bytes(data[:half])
    (tmp_path / "s.zip.002").write_bytes(data[half:])
    return tmp_path / "s.zip.001"


@pytest.mark.parametrize("kind", ["spanned-path", "spanned-list", "split-path"])
def test_a_volume_set_is_refused_under_pipe(kind: str, tmp_path: Path) -> None:
    # One stream cannot join a set's parts; the refusal says so instead of asking for
    # the parts the caller already gave.
    if kind == "spanned-path":
        source: object = SPANNED_ZIP / "set.zip"
    elif kind == "spanned-list":
        source = [SPANNED_ZIP / name for name in ("set.z01", "set.z02", "set.zip")]
    else:
        source = _split_zip(tmp_path)
    with pytest.raises(ArchiveyUsageError, match="volume set of") as info:
        archivey.open_archive(source, pipe=True)  # type: ignore[call-overload]  # source kinds vary
    assert "without pipe=True" in str(info.value)
    with archivey.open_archive(source, streaming=True) as reader:  # type: ignore[call-overload]  # source kinds vary
        assert [m for m, _ in reader.stream_members()]


@pytest.mark.skipif(
    not unrar_reads_from_pipes(), reason="requires RARLAB unrar 7.00 or later"
)
def test_a_rar_volume_set_is_refused_under_pipe() -> None:
    with pytest.raises(
        StreamNotSeekableError, match="cannot be read as a pipe"
    ) as info:
        archivey.open_archive(RAR_FIXTURES / "stdin_vol.part1.rar", pipe=True)
    message = str(info.value)
    assert "without pipe=True" in message
    assert "Open the volumes as files" not in message
