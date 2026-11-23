"""Public ``open_stream``: forward-only by default, seekable on demand."""

from __future__ import annotations

import gzip
import io
import lzma
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveMember,
    ArchiveReader,
    ArchiveStream,
    ArchiveyUsageError,
    ContainerFormat,
    FormatDetectionError,
    MemberType,
    StreamFormat,
    open_archive,
    open_stream,
)
from tests.sample_archives import (
    CORPUS,
    FORMAT_KEYS,
    CorpusEntry,
    corpus_archive_path,
    skip_unless_runnable,
)

CONTENT = b"the quick brown fox jumps over the lazy dog\n" * 50


def test_open_stream_default_is_forward_only() -> None:
    compressed = gzip.compress(CONTENT)
    with open_stream(io.BytesIO(compressed)) as stream:
        assert isinstance(stream, ArchiveStream)
        assert stream.seekable() is False
        with pytest.raises(io.UnsupportedOperation):
            stream.seek(0)
        assert stream.tell() == 0
        assert stream.read() == CONTENT


def test_open_stream_seekable_true_allows_seek() -> None:
    compressed = gzip.compress(CONTENT)
    with open_stream(io.BytesIO(compressed), seekable=True) as stream:
        assert stream.seekable() is True
        assert stream.read(10) == CONTENT[:10]
        assert stream.seek(0) == 0
        assert stream.read(10) == CONTENT[:10]


def test_open_stream_explicit_format() -> None:
    compressed = gzip.compress(CONTENT)
    with open_stream(io.BytesIO(compressed), format=StreamFormat.GZIP) as stream:
        assert stream.read() == CONTENT


def test_open_stream_archive_format_raw_stream() -> None:
    compressed = gzip.compress(CONTENT)
    with open_stream(io.BytesIO(compressed), format=ArchiveFormat.GZ) as stream:
        assert stream.read() == CONTENT


@pytest.mark.parametrize("fmt", [ArchiveFormat.ZIP, ArchiveFormat.TAR, "tar"])
def test_open_stream_rejects_container_format(fmt: ArchiveFormat | str) -> None:
    # An uncompressed tar is refused like a ZIP: it has no compression layer to peel.
    with pytest.raises(ArchiveyUsageError, match="container format"):
        open_stream(io.BytesIO(b"PK"), format=fmt)


def test_open_stream_rejects_detected_container(tmp_path: Path) -> None:
    import zipfile

    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("a.txt", "hi")
    with pytest.raises(FormatDetectionError, match="Not a single-file") as info:
        open_stream(path)
    # The format is named once, by the source_format attribute, not also in the prose.
    assert str(info.value).count("ZIP") == 1
    assert "ArchiveFormat" not in str(info.value)


def test_open_stream_rejects_detected_plain_tar(tmp_path: Path) -> None:
    # A plain tar has no compression layer to peel, so it stays a container to
    # open_stream, like a ZIP.
    import tarfile

    path = tmp_path / "a.tar"
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = 2
        tf.addfile(info, io.BytesIO(b"hi"))
    with pytest.raises(FormatDetectionError, match="Not a single-file"):
        open_stream(path)


# Every corpus archive built as a compressed tar: the outer codec is what open_stream
# peels. Derived from the corpus format table, so a compressed-tar key added there is
# covered here with no edit.
_COMPRESSED_TAR_CASES = [
    pytest.param(entry, key, id=f"{entry.id}-{key}")
    for entry in CORPUS
    for key in entry.formats
    if FORMAT_KEYS[key].container is ContainerFormat.TAR
    and FORMAT_KEYS[key].stream is not StreamFormat.UNCOMPRESSED
]


def _snapshot(reader: ArchiveReader) -> list[tuple[ArchiveMember, bytes | None]]:
    return [
        (
            member,
            reader.read(member) if member.type is MemberType.FILE else None,
        )
        for member in reader.members()
    ]


def _stream_snapshot(
    reader: ArchiveReader,
) -> list[tuple[ArchiveMember, bytes | None]]:
    return [
        (member, stream.read() if stream is not None else None)
        for member, stream in reader.stream_members()
    ]


@pytest.mark.parametrize(("entry", "key"), _COMPRESSED_TAR_CASES)
def test_open_stream_peels_compressed_tar(
    entry: CorpusEntry, key: str, tmp_path: Path
) -> None:
    """open_archive(open_stream(p)) reads what open_archive(p) reads.

    open_stream removes the compression layer only and returns the tar bytes, as
    gzip.open does for a .tar.gz. Only the reader's format can see the outer layer;
    the members (every compared field) and their data are the same.
    """
    skip_unless_runnable(entry, key)
    path = corpus_archive_path(entry, key, tmp_path)
    tar_format = FORMAT_KEYS[key]

    with open_archive(path) as direct:
        assert direct.format == tar_format
        expected = _snapshot(direct)

    with (
        open_stream(path, seekable=True) as stream,
        open_archive(stream) as peeled,
    ):
        assert peeled.format == ArchiveFormat.TAR
        assert _snapshot(peeled) == expected

    # The default forward-only stream is a non-seekable source, which open_archive
    # reads only under pipe=True, as it reads a pipe.
    with open_archive(path, streaming=True) as direct:
        expected_pass = _stream_snapshot(direct)
    with open_stream(path) as stream, open_archive(stream, pipe=True) as peeled:
        assert peeled.format == ArchiveFormat.TAR
        assert _stream_snapshot(peeled) == expected_pass

    # Detected, explicit compressed-tar and explicit raw-stream formats all peel the
    # same layer and read the same bytes.
    raw_format = ArchiveFormat(ContainerFormat.RAW_STREAM, tar_format.stream)
    with open_stream(path, format=raw_format) as raw:
        expected_bytes = raw.read()
    formats: list[ArchiveFormat | str | None] = [None, tar_format]
    if hasattr(ArchiveFormat, tar_format.display_name):
        # Only the named pairs have string spellings (backend-registry).
        formats.append(tar_format.file_extension())
    for fmt in formats:
        with open_stream(path, format=fmt) as stream:
            assert stream.read() == expected_bytes, fmt

    # A BinaryIO source takes the same peel: detection reads its prefix through the
    # ArchiveSource replay buffer, not from a path.
    data = path.read_bytes()
    for fmt in (None, tar_format):
        with open_stream(io.BytesIO(data), format=fmt) as stream:
            assert stream.read() == expected_bytes, fmt


def test_open_stream_path_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "data.gz"
    path.write_bytes(gzip.compress(CONTENT))
    with open_stream(path) as stream:
        assert stream.read() == CONTENT


def test_open_stream_xz_default_builds_no_index() -> None:
    """Without seekable=True, XZ does not expose a cheap index-derived size."""
    compressed = lzma.compress(CONTENT, format=lzma.FORMAT_XZ)
    with open_stream(io.BytesIO(compressed)) as stream:
        assert stream.seekable() is False
        assert stream.size is None
        assert stream.read() == CONTENT


def test_open_stream_xz_seekable_exposes_size() -> None:
    compressed = lzma.compress(CONTENT, format=lzma.FORMAT_XZ)
    with open_stream(io.BytesIO(compressed), seekable=True) as stream:
        assert stream.seekable() is True
        assert stream.size == len(CONTENT)
        assert stream.seek(10) == 10
        assert stream.read(5) == CONTENT[10:15]
