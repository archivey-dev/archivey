"""archivey never closes a stream the caller handed it.

``archive-reading`` states it as a rule ("Archivey SHALL never close a caller-supplied
``BinaryIO``") and the stream layer keeps it by borrowing rather than owning. Those are
both about *wrappers*, though, and a rule about wrappers can be broken from outside them:
a caller's own object reaching a backend unwrapped is one owning wrapper away from being
closed. ``SeekCountingStream`` is such a wrapper, in the ZIP and compressed-TAR close
chains whenever measurement is on.

So this module tests the rule end to end, at the entry points, over the object the caller
actually passed: every format from a stream, both of the two commonest stream shapes, with
measurement on and off. A per-class ownership decision is checked in
``test_stream_bases.py``; this is the property those decisions exist to produce, and it
holds no matter which wrapper a backend puts in front of the source.

"Not closed" is the weaker half of the claim. Each test also reads from the stream
afterwards: a stream that survives as an object but not as a source is no use to the
caller who still owns it.
"""

from __future__ import annotations

import io
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

import pytest

from archivey import (
    ArchiveReader,
    ArchiveyConfig,
    ArchiveyError,
    open_archive,
    open_stream,
)
from archivey.internal.measurement import enable_measurement
from archivey.internal.volumes import resolve_source
from tests.sample_archives import (
    CORPUS,
    CorpusEntry,
    corpus_archive_path,
    skip_unless_runnable,
)

_BASIC = next(entry for entry in CORPUS if entry.id == "basic")
# Every format the entry is built in except ``dir``, which is a directory tree: there is
# no stream to hand over, so there is nothing here to close.
_STREAM_KEYS = [key for key in _BASIC.formats if key != "dir"]
# The BytesIO shape has no name, so the magic-less formats (``tar.zz``, ``tar.br``,
# ``tar.lzma``) are recognised only with every content probe on.
_ALWAYS_PROBE = ArchiveyConfig(always_probe_content=True)


class _CallerBytesIO(io.BytesIO):
    """The commonest caller shape, and the one the ZIP close bug rode in on."""


def _caller_streams(path: Path) -> Iterator[tuple[str, BinaryIO]]:
    """The two shapes a caller realistically hands to ``open_archive``.

    Both are already buffered, so the boundary adds no full-count layer to either; the
    borrow wrapper is the only thing between them and a backend.
    """
    yield "bytesio", _CallerBytesIO(path.read_bytes())
    with open(path, "rb") as handle:
        yield "file", handle


def _assert_still_the_caller_s(
    stream: BinaryIO, expected_head: bytes, label: str = ""
) -> None:
    assert not stream.closed, label
    stream.seek(0)
    assert stream.read(len(expected_head)) == expected_head, label


def _read_everything(reader: ArchiveReader) -> None:
    for member in reader.members():
        if member.is_file:
            with reader.open(member) as stream:
                stream.read()


@pytest.mark.parametrize("key", _STREAM_KEYS)
@pytest.mark.parametrize("measure", [False, True], ids=["plain", "measured"])
def test_open_archive_never_closes_a_caller_stream(
    key: str, measure: bool, tmp_path: Path
) -> None:
    """Both shapes, every format, read to the end and closed.

    ``measure`` is not decoration: with measurement off every row here passed before the
    fix, and ZIP / TAR.GZ / TAR.BZ2 failed on every shape with it on. It is the benchmark
    harness's switch, so no ordinary caller could reach the bug — which is why nothing
    caught it, not a reason it was allowed.
    """
    skip_unless_runnable(_BASIC, key)
    path = corpus_archive_path(_BASIC, key, tmp_path)
    head = path.read_bytes()[:16]

    for shape, stream in _caller_streams(path):
        if measure:
            with (
                enable_measurement(),
                open_archive(stream, config=_ALWAYS_PROBE) as reader,
            ):
                _read_everything(reader)
        else:
            with open_archive(stream, config=_ALWAYS_PROBE) as reader:
                _read_everything(reader)
        _assert_still_the_caller_s(stream, head, shape)


@pytest.mark.parametrize("measure", [False, True], ids=["plain", "measured"])
def test_open_stream_never_closes_a_caller_stream(
    measure: bool, tmp_path: Path
) -> None:
    """The single-file entry point normalises its source the same way."""
    entry: CorpusEntry = next(e for e in CORPUS if "gz" in e.formats)
    skip_unless_runnable(entry, "gz")
    path = corpus_archive_path(entry, "gz", tmp_path)
    head = path.read_bytes()[:16]

    for shape, stream in _caller_streams(path):
        if measure:
            with enable_measurement(), open_stream(stream) as decompressed:
                decompressed.read()
        else:
            with open_stream(stream) as decompressed:
                decompressed.read()
        _assert_still_the_caller_s(stream, head, shape)


class _RawSeekable(io.RawIOBase):
    """A seekable raw stream with no buffer: the shape the source buffers for itself."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, b) -> int:  # type: ignore[override]  # test double; broad buffer type
        return self._inner.readinto(b)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        return self._inner.seek(offset, whence)

    def tell(self, /) -> int:
        return self._inner.tell()


@pytest.mark.parametrize("outcome", ["read", "refused"])
def test_open_stream_closes_the_source_it_built(
    outcome: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``open_stream``'s source closes with the stream it returns, or with the refusal.

    Over a seekable raw stream the source owns a read buffer of its own; closing the
    source detaches it. Nothing else would: the caller holds only the returned stream.
    Fails against returning the codec stream without tying the source to it, and
    against a refusal that leaves the built source open: here a payload no detector
    claims, so ``_resolve_stream_format`` raises and the source must close on the way
    out.
    """
    import gzip

    from archivey.internal.source import ArchiveSource

    built: list[ArchiveSource] = []
    for_stream = ArchiveSource.for_stream.__func__  # type: ignore[attr-defined]

    def _recording(cls, stream, **kwargs):
        source = for_stream(cls, stream, **kwargs)
        built.append(source)
        return source

    monkeypatch.setattr(ArchiveSource, "for_stream", classmethod(_recording))
    if outcome == "read":
        caller = _RawSeekable(gzip.compress(b"hello world" * 10))
        with open_stream(caller) as decompressed:
            assert decompressed.read() == b"hello world" * 10
    else:
        caller = _RawSeekable(b"not compressed at all" * 10)
        with pytest.raises(ArchiveyError):
            open_stream(caller)
    assert len(built) == 1
    assert built[0].closed
    assert not caller.closed


def test_a_sequence_of_caller_streams_is_not_closed() -> None:
    """The join borrows the caller's stream parts directly, with no wrapper between.

    The items ``ConcatenatedFile`` joins here are the caller's own objects, so this is
    the test that it never closes one. The other half of the same guarantee, that the
    join gathers a short-reading part, is
    ``test_a_joined_set_closes_with_the_source_and_borrows_its_stream_parts`` in
    ``tests/test_archive_source.py``.
    """
    parts = [_CallerBytesIO(b"first half"), _CallerBytesIO(b"second half")]
    # A list of BytesIO is a valid source sequence at runtime; typeshed models
    # io.BytesIO and typing.BinaryIO as unrelated, so the sequence does not match.
    resolved = resolve_source(parts)  # type: ignore[arg-type]
    assert resolved.volume_count == 2
    joined = resolved.source
    assert joined.joined is not None
    assert joined.read() == b"first halfsecond half"
    joined.close()
    for part in parts:
        _assert_still_the_caller_s(part, b"first" if part is parts[0] else b"second")


def test_a_member_stream_read_as_an_archive_is_not_closed(tmp_path: Path) -> None:
    """A nested archive: the outer reader's member stream is the inner reader's source.

    The caller here is archivey's own user reading an archive inside an archive, and the
    stream they hold is an ``ArchiveStream``. Closing the inner reader must leave the
    outer member readable — otherwise reading a second member after a nested open fails.
    """
    skip_unless_runnable(_BASIC, "tar")
    inner_path = corpus_archive_path(_BASIC, "tar", tmp_path)
    outer_path = tmp_path / "outer.zip"
    import zipfile

    with zipfile.ZipFile(outer_path, "w") as zf:
        zf.write(inner_path, "inner.tar")
        zf.writestr("after.txt", b"still readable")

    # seekable_members: a ZIP member stream is forward-only by default, and a nested
    # TAR would then have to be opened streaming=True — a different path from the one
    # this test is about.
    with open_archive(outer_path, seekable_members=True) as outer:
        member_stream = outer.open("inner.tar")
        with open_archive(member_stream) as inner:
            _read_everything(inner)
        assert not member_stream.closed
        member_stream.close()
        # The outer reader is unharmed: its next member still reads.
        assert outer.read("after.txt") == b"still readable"


@pytest.mark.parametrize("key", ["zip", "7z", "rar"])
def test_a_failed_open_does_not_close_the_caller_s_stream(
    key: str, tmp_path: Path
) -> None:
    """The error path releases what the reader opened, and must stop at the same place.

    A backend that fails in ``__init__`` closes the stream it owns before re-raising —
    that is deliberate, so a catch-and-continue loop does not hold a handle in a
    traceback. The caller's stream is not what it owns, and a caller who wants to try a
    different ``format=`` on the same bytes needs it back.

    The three keys are the ones whose first 64 bytes actually reach a backend and fail
    there, measured on this HEAD: ``zip`` raises from ``zip_reader.__init__``, ``7z``
    from ``sevenzip_reader.__init__``, ``rar`` from ``rar_reader.__init__``. A RAR cut
    inside a header opens and lists the members before the cut, so the ``rar`` key
    also damages the main header's CRC, which is refused at open. A ZIP cut inside a
    member's data opens and lists that member, so the ``zip`` key is cut inside the
    first local header instead. The other
    formats do not exercise this path and are deliberately absent: a truncated ``tar``
    or ``iso`` is refused by detection, before any backend is constructed, and a
    truncated ``tar.gz`` *opens* — the gzip member header is intact and the truncation
    surfaces later, during listing, which is the different release path the next
    paragraph excludes.
    """
    skip_unless_runnable(_BASIC, key)
    truncated = corpus_archive_path(_BASIC, key, tmp_path).read_bytes()[:64]
    if key == "zip":
        truncated = truncated[:20]
    if key == "rar":
        # The RAR5 main header's CRC starts at byte 8, after the signature.
        truncated = truncated[:8] + bytes([truncated[8] ^ 0xFF]) + truncated[9:]
    stream = _CallerBytesIO(truncated)
    # Around the open alone: a failure three members into a read would exercise a
    # different release path, and this test names the one in ``__init__``.
    with enable_measurement(), pytest.raises(ArchiveyError):
        open_archive(stream)
    _assert_still_the_caller_s(stream, truncated[:16], key)
