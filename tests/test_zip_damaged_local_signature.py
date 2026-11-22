"""A ZIP read from a pipe goes past a local header whose signature is damaged
(``openspec/changes/archive/2026-11-21-salvage-step-2-zip``).

A file read lists every member from the central directory, and the read of the one
whose local signature is damaged fails (``Bad magic number for file header``), as
``unzip`` ("bad zipfile offset (local header sig)") and 7-Zip ("Headers Error") fail
it. A pipe has no directory until the end: it now takes the damaged header's sizes,
confirmed by the ZIP signature where its data ends, and goes on, so it lists and reads
the same as the file, without holding the rest of the stream.
"""

from __future__ import annotations

import io
import os
import zipfile

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.config import ListingLimits
from archivey.exceptions import ArchiveyError, CorruptionError, UnsupportedFeatureError
from archivey.internal.backends import zip_local_walk
from archivey.internal.backends.rar_forward import KEEP_BYTES


class _Pipe(io.RawIOBase):
    def __init__(self, data: bytes) -> None:
        self._data = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
        data = self._data.read(min(len(buffer), 4093))
        memoryview(buffer).cast("B")[: len(data)] = data
        return len(data)


def _build(
    contents: list[bytes], method: int = zipfile.ZIP_DEFLATED
) -> tuple[bytes, list[int]]:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as archive:
        for index, content in enumerate(contents):
            archive.writestr(f"dir/file{index}.txt", content)
    data = buf.getvalue()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        offsets = [info.header_offset for info in archive.infolist()]
    return data, offsets


_CONTENTS = [bytes([65 + i]) * n for i, n in enumerate((100, 2000, 3000, 50, 0))]


def _flip(data: bytes, offset: int) -> bytes:
    out = bytearray(data)
    out[offset] ^= 0x41
    return bytes(out)


def _pass(
    data: bytes, access: str, config: ArchiveyConfig | None = None
) -> tuple[list[tuple[str, object]], BaseException | None]:
    source: object = (
        io.BufferedReader(_Pipe(data)) if access == "pipe" else io.BytesIO(data)
    )
    seen: list[tuple[str, object]] = []
    error: BaseException | None = None
    with open_archive(source, streaming=access != "random", config=config) as reader:  # type: ignore[arg-type]
        try:
            for member, stream in reader.stream_members():
                assert stream is not None
                try:
                    content: object = stream.read()
                except CorruptionError as exc:
                    content = str(exc)
                seen.append((member.name, content))
        except ArchiveyError as exc:
            error = exc
    return seen, error


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
@pytest.mark.parametrize("access", ["random", "pipe"])
def test_a_damaged_local_signature_fails_that_member_only(
    method: int, access: str
) -> None:
    data, offsets = _build(_CONTENTS, method)
    seen, error = _pass(_flip(data, offsets[2] + 1), access)
    assert error is None
    assert [name for name, _ in seen] == [f"dir/file{i}.txt" for i in range(5)]
    for index, (_, content) in enumerate(seen):
        if index == 2:
            assert isinstance(content, str)
            assert "Bad magic number for file header" in content
        else:
            assert content == _CONTENTS[index]


def test_the_pipe_hold_is_the_rar_one() -> None:
    assert zip_local_walk._DAMAGED_HEADER_HOLD == KEEP_BYTES


def test_the_pipe_goes_past_the_damage_without_holding_the_rest() -> None:
    """With listing limits that keep only a few hundred KiB after the walk's end,
    the members after the damage were out of reach from a pipe; followed by its
    sizes, the damaged header no longer ends the walk there."""
    contents = [b"a" * 100, b"b" * 100, os.urandom(600_000), b"d" * 50]
    data, offsets = _build(contents, zipfile.ZIP_STORED)
    damaged = _flip(data, offsets[1] + 1)
    config = ArchiveyConfig(
        listing_limits=ListingLimits(max_members=10, max_metadata_bytes=1000)
    )
    seen, error = _pass(damaged, "pipe", config)
    assert error is None
    assert [content for _, content in seen][2:] == contents[2:]
    assert "Bad magic number" in str(seen[1][1])


def test_a_damaged_signature_on_a_member_with_a_data_descriptor_is_not_followed() -> (
    None
):
    """Bit 3 leaves the sizes to the descriptor, so the header names no size to
    follow. From a pipe the member before it already fails to end (its descriptor
    must have a ZIP signature after it), and the walk stops there as before; a file
    lists every member from the directory."""
    raw = io.BytesIO()
    # A non-seekable writer sets bit 3 on every member.
    with zipfile.ZipFile(_Unseekable(raw), "w", zipfile.ZIP_DEFLATED) as archive:
        for index, content in enumerate(_CONTENTS):
            archive.writestr(f"dir/file{index}.txt", content)
    data = raw.getvalue()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        assert all(info.flag_bits & 0x08 for info in infos)
        offsets = [info.header_offset for info in infos]
    random, _ = _pass(_flip(data, offsets[2] + 1), "random")
    pipe, pipe_error = _pass(_flip(data, offsets[2] + 1), "pipe")
    assert [name for name, _ in random] == [f"dir/file{i}.txt" for i in range(5)]
    assert [name for name, _ in pipe] == ["dir/file0.txt", "dir/file1.txt"]
    assert isinstance(pipe_error, CorruptionError)
    assert "no data descriptor after member #1" in str(pipe_error)


@pytest.mark.parametrize(
    ("method", "error_type", "message"),
    [
        (zipfile.ZIP_STORED, UnsupportedFeatureError, "seekable source"),
        (zipfile.ZIP_DEFLATED, CorruptionError, "no data descriptor after member #1"),
    ],
)
def test_a_damaged_signature_after_a_data_descriptor_member_is_not_followed(
    method: int, error_type: type[ArchiveyError], message: str
) -> None:
    """Only the member before the damage keeps its sizes in a descriptor. The pipe
    accepts that descriptor only with an intact signature after it, and the damaged
    one is not intact, so the pass ends at that member as before; a file lists every
    member from the directory (the spec's data-descriptor limit)."""
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        for index, content in enumerate(_CONTENTS):
            archive._seekable = index != 1  # type: ignore[attr-defined]  # bit 3 on #1 only
            info = zipfile.ZipInfo(f"dir/file{index}.txt", (2020, 1, 1, 0, 0, 0))
            info.compress_type = method
            with archive.open(info, "w") as out:
                out.write(content)
        archive._seekable = True  # type: ignore[attr-defined]
    data = raw.getvalue()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()
        assert [bool(info.flag_bits & 0x08) for info in infos] == [
            False,
            True,
            False,
            False,
            False,
        ]
        assert all(info.compress_type == method for info in infos)
        offsets = [info.header_offset for info in infos]
    damaged = _flip(data, offsets[2] + 1)
    random, random_error = _pass(damaged, "random")
    assert random_error is None
    assert [name for name, _ in random] == [f"dir/file{i}.txt" for i in range(5)]
    pipe, pipe_error = _pass(damaged, "pipe")
    names = [name for name, _ in pipe]
    assert names[:1] == ["dir/file0.txt"]
    assert "dir/file2.txt" not in names
    assert isinstance(pipe_error, error_type)
    assert message in str(pipe_error)


class _Unseekable(io.RawIOBase):
    def __init__(self, out: io.BytesIO) -> None:
        self._out = out

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def write(self, data: bytes) -> int:  # type: ignore[override]
        return self._out.write(data)

    def flush(self) -> None:
        pass


def test_a_damaged_header_with_a_size_no_zip64_field_holds_is_not_followed() -> None:
    """The uncompressed size deferred to a ZIP64 field the header lacks: the header
    is not followed, and the walk takes the old path, which still reads the members
    after it from the bytes held for the directory."""
    data, offsets = _build(_CONTENTS, zipfile.ZIP_STORED)
    out = bytearray(_flip(data, offsets[2] + 1))
    out[offsets[2] + 22 : offsets[2] + 26] = b"\xff\xff\xff\xff"
    seen, error = _pass(bytes(out), "pipe")
    assert [name for name, _ in seen] == [
        "dir/file0.txt",
        "dir/file1.txt",
        "dir/file3.txt",
        "dir/file4.txt",
    ]
    assert [content for _, content in seen] == [_CONTENTS[i] for i in (0, 1, 3, 4)]
    assert isinstance(error, CorruptionError)
    assert "dir/file2.txt" in str(error)


@pytest.mark.parametrize(
    ("size", "followed"),
    [(KEEP_BYTES - 200, True), (KEEP_BYTES, False)],
)
def test_the_pipe_follows_a_damaged_header_only_within_its_hold(
    size: int, followed: bool
) -> None:
    contents = [b"a" * 10, os.urandom(size), b"c" * 10]
    data, offsets = _build(contents, zipfile.ZIP_STORED)
    seen, error = _pass(_flip(data, offsets[1] + 1), "pipe")
    names = [name for name, _ in seen]
    if followed:
        assert error is None
        assert names == ["dir/file0.txt", "dir/file1.txt", "dir/file2.txt"]
        assert "Bad magic number" in str(seen[1][1])
    else:
        assert names == ["dir/file0.txt", "dir/file2.txt"]
        assert isinstance(error, CorruptionError)
        assert "dir/file1.txt" in str(error)
    assert seen[-1][1] == contents[2]
