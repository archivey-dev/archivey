"""Non-file open/read contract: directories and ANTI raise ArchiveyUsageError, and a
directory that declares data gives the same bytes through ``open()`` and through
``stream_members()``."""

from __future__ import annotations

import io
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import pytest

from archivey import ArchiveReader, DiagnosticCode, open_archive
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    UnsupportedFeatureError,
)
from archivey.types import MemberType
from tests.conftest import requires, requires_binary
from tests.streams_util import NonSeekableBytesIO, open_mode


def _assert_dir_open_raises(archive_path: Path) -> None:
    with open_archive(archive_path) as reader:
        directory = next(m for m in reader.members() if m.is_dir)
        with pytest.raises(ArchiveyUsageError, match="not a file"):
            reader.open(directory)
        with pytest.raises(ArchiveyUsageError, match="not a file"):
            reader.read(directory)
        for member, stream in reader.stream_members():
            if member.is_dir:
                assert stream is None
            elif stream is not None:
                stream.close()


def test_zip_directory_open_raises(tmp_path: Path) -> None:
    archive = tmp_path / "dirs.zip"
    with ZipFile(archive, "w") as zf:
        zf.writestr("adir/", "")
        zf.writestr("adir/f.txt", b"hi")
    _assert_dir_open_raises(archive)


def test_tar_directory_open_raises(tmp_path: Path) -> None:
    root = tmp_path / "tree"
    (root / "adir").mkdir(parents=True)
    (root / "adir" / "f.txt").write_bytes(b"hi")
    archive = tmp_path / "dirs.tar"
    with tarfile.open(archive, "w") as tf:
        tf.add(root / "adir", arcname="adir")
    _assert_dir_open_raises(archive)


def test_directory_backend_open_raises(tmp_path: Path) -> None:
    root = tmp_path / "plain"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "f.txt").write_bytes(b"x")
    _assert_dir_open_raises(root)


@requires("pycdlib")
def test_iso_directory_open_raises(tmp_path: Path) -> None:
    from tests.test_iso import _build_iso

    path = tmp_path / "rr.iso"
    path.write_bytes(_build_iso(rock_ridge=True, joliet=True))
    with open_archive(path) as reader:
        directory = next(m for m in reader.members() if m.is_dir)
        assert directory.type is MemberType.DIRECTORY
        with pytest.raises(ArchiveyUsageError, match="not a file"):
            reader.read(directory)


# --- a directory entry that declares data: the same bytes in both access modes ---------

# What one member gives: its bytes, ``None`` when there is nothing to deliver (the pass
# yields no stream; ``open()`` refuses with "not a file"), or the class of the error
# reading it raises.
_Outcome = bytes | None | type[BaseException]


def _zip_directory_data(tmp_path: Path, shape: str) -> Path:
    """``d/`` carrying 12 bytes, a file under it, and ``e/`` with no data."""
    path = tmp_path / f"{shape}.zip"
    method = zipfile.ZIP_DEFLATED if shape == "zip-deflate" else zipfile.ZIP_STORED
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(zipfile.ZipInfo("d/"), b"hidden data!", compress_type=method)
        zf.writestr("d/f.txt", b"visible")
        zf.writestr(zipfile.ZipInfo("e/"), b"")
    data = bytearray(path.read_bytes())
    central = data.index(b"PK\x01\x02")
    if shape == "zip-zero-crc":
        # A directory's conventional CRC-32 field: no digest, so DIGEST_UNVERIFIABLE.
        struct.pack_into("<I", data, 14, 0)
        struct.pack_into("<I", data, central + 16, 0)
    elif shape == "zip-bad-crc":
        assert data.count(b"hidden data!") == 1
        data = bytearray(data.replace(b"hidden data!", b"XXXXXXXXXXXX"))
    path.write_bytes(bytes(data))
    return path


def _tar_directory_data(tmp_path: Path, shape: str) -> Path:
    from tests.test_tar import _DAMAGED_TRAILER, _tar_entry_with_data

    if shape == "tar-dirtype-no-blocks":
        # A DIRTYPE header with a size and a member header right after it: listed
        # with no size and no report, so open() refuses it and the pass yields none.
        data = _tar_entry_with_data(
            tarfile.DIRTYPE, data=b"", size_field=b"%011o\0" % 4096
        )
    elif shape == "tar-dirtype-before-trailer":
        # The same header as the last member, the walk ending on a zero block inside
        # the declared span: the blocks cannot be told from the trailer, so it lists
        # with no size, MEMBER_DIRECTORY_DATA_IGNORED reports it, and nothing reads.
        data = _tar_entry_with_data(
            tarfile.DIRTYPE,
            data=b"",
            size_field=b"%011o\0" % 4096,
            tail=_DAMAGED_TRAILER,
        )
    else:
        typeflag = tarfile.AREGTYPE if shape == "tar-old-style-nul" else tarfile.REGTYPE
        data = _tar_entry_with_data(typeflag)
    path = tmp_path / f"{shape}.tar"
    path.write_bytes(data)
    return path


class _UnseekableSink(io.RawIOBase):
    """A write target that cannot seek, so ``zipfile`` sets bit 3 on every entry and
    writes each member's sizes and CRC-32 in a data descriptor after its data."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def write(self, b: Any) -> int:
        self.data += b
        return len(b)


def _zip_bit3_directory_data(tmp_path: Path, shape: str) -> Path:
    """``d/`` carrying 12 bytes and ``e/`` with none, both written with a data
    descriptor (bit 3), as every ZIP written to a pipe or a socket is."""
    sink = _UnseekableSink()
    with zipfile.ZipFile(sink, "w") as zf:
        zf.writestr(zipfile.ZipInfo("d/"), b"hidden data!")
        zf.writestr("d/f.txt", b"visible")
        zf.writestr(zipfile.ZipInfo("e/"), b"")
    data = bytes(sink.data)
    assert struct.unpack_from("<H", data, 6)[0] & 0x8  # bit 3 on the first entry
    path = tmp_path / f"{shape}.zip"
    path.write_bytes(data)
    return path


def _rar_directory_data(tmp_path: Path, shape: str) -> Path:
    from tests.test_audit_rar_iso_dir import (
        _FIXTURES,
        _rar5_build,
        _rar5_file_blocks,
        _rar5_parse,
        _rar_with_directory_data,
    )

    if shape != "rar-solid-stored":
        return _rar_with_directory_data(tmp_path, stored=shape == "rar-stored")
    # The solid fixture's last entry is the directory ``subdir``: give it a stored
    # body. It comes after every file, so no file's solid stream depends on it.
    blocks = _rar5_parse((_FIXTURES / "basic_solid__.rar").read_bytes())
    last = _rar5_file_blocks(blocks)[-1]
    assert last["name"] == b"subdir" and last["file_flags"] & 1
    last["data"] = b"stored dir data"
    last["unpacked"] = len(last["data"])
    last["crc"] = struct.pack("<I", zlib.crc32(last["data"]))
    last["cinfo"] = 0
    path = tmp_path / "solid_dir.rar"
    path.write_bytes(_rar5_build(blocks))
    return path


def _sevenzip_directory(tmp_path: Path, shape: str) -> Path:
    # 7z has no directory with data: a record with a stream is a FILE (DR-25), so
    # the directory here has none, and both modes give it nothing.
    import py7zr

    tree = tmp_path / "tree" / "sub"
    tree.mkdir(parents=True)
    (tree / "f.txt").write_bytes(b"hi")
    path = tmp_path / "dir.7z"
    with py7zr.SevenZipFile(path, "w") as zf:
        zf.writeall(tree, "sub")
    return path


def _random_access_outcomes(path: Path) -> dict[str, _Outcome]:
    outcomes: dict[str, _Outcome] = {}
    with open_archive(path) as reader:
        for member in reader.members():
            try:
                outcomes[member.name] = reader.read(member)
            except ArchiveyUsageError as exc:
                assert "not a file" in str(exc)
                outcomes[member.name] = None
            except ArchiveyError as exc:
                outcomes[member.name] = type(exc)
    return outcomes


def _pass_outcomes(reader: ArchiveReader) -> dict[str, _Outcome]:
    outcomes: dict[str, _Outcome] = {}
    for member, stream in reader.stream_members():
        if stream is None:
            outcomes[member.name] = None
            continue
        try:
            outcomes[member.name] = stream.read()
        except ArchiveyError as exc:
            outcomes[member.name] = type(exc)
    return outcomes


_ZIP_OUTCOMES: dict[str, _Outcome] = {
    "d/": b"hidden data!",
    "d/f.txt": b"visible",
    "e/": None,
}

# Per shape: its builder, then what random access gives for the members named. A
# shape whose files are long lists only its directories, which are the point.
_SHAPES: dict[str, tuple[Callable[[Path, str], Path], dict[str, _Outcome]]] = {
    "zip-stored": (_zip_directory_data, _ZIP_OUTCOMES),
    "zip-deflate": (_zip_directory_data, _ZIP_OUTCOMES),
    "zip-zero-crc": (_zip_directory_data, _ZIP_OUTCOMES),
    "zip-bad-crc": (_zip_directory_data, {**_ZIP_OUTCOMES, "d/": CorruptionError}),
    "zip-bit3": (_zip_bit3_directory_data, _ZIP_OUTCOMES),
    "tar-old-style-nul": (
        _tar_directory_data,
        {"d/": b"hello directory", "after.txt": b"after\n"},
    ),
    "tar-old-style-regtype": (
        _tar_directory_data,
        {"d/": b"hello directory", "after.txt": b"after\n"},
    ),
    "tar-dirtype-no-blocks": (
        _tar_directory_data,
        {"d/": None, "after.txt": b"after\n"},
    ),
    "tar-dirtype-before-trailer": (_tar_directory_data, {"d/": None}),
    "7z": (_sevenzip_directory, {"sub/": None, "sub/f.txt": b"hi"}),
    "rar-stored": (_rar_directory_data, {"-inul/": b"stored dir data"}),
    "rar-compressed": (_rar_directory_data, {"-inul/": UnsupportedFeatureError}),
    "rar-solid-stored": (
        _rar_directory_data,
        {
            "file1.txt": b"Hello, world!",
            "empty_subdir/": None,
            "subdir/": b"stored dir data",
        },
    ),
}

# The one shape where a pass from a source that cannot seek differs: a bit-3 entry
# declares its size in the data descriptor after its data, so the pass meets the
# directory before it can know the directory declares data, and yields no stream.
# The listing still reports MEMBER_DIRECTORY_DATA_IGNORED once the central directory
# arrives (``format-zip``, "Two shapes read differently from a pipe").
_PIPE_DIFFERS: dict[str, dict[str, _Outcome]] = {"zip-bit3": {"d/": None}}


def _shape_params() -> list[Any]:
    marks = {"7z": requires("py7zr")}
    params: list[Any] = []
    for shape in _SHAPES:
        if shape.startswith("rar"):
            params.append(pytest.param(shape, marks=requires_binary("unrar")))
        elif shape in marks:
            params.append(pytest.param(shape, marks=marks[shape]))
        else:
            params.append(shape)
    return params


@pytest.mark.parametrize("shape", _shape_params())
def test_directory_data_is_the_same_in_a_pass_and_in_random_access(
    tmp_path: Path, shape: str
) -> None:
    """``stream_members()`` yields a stream for exactly the directories ``open()``
    reads, with the same bytes and the same checks: a CRC that fails raises in both,
    data archivey cannot decode is refused in both, a directory with no data (or a
    TAR ``DIRTYPE`` size that cannot be told from the trailer) gets nothing in both.
    The pass is checked on a random-access reader and on a forward-only one: of a
    source that cannot seek for ZIP and TAR, ``streaming=True`` over the file for the
    others. ``_PIPE_DIFFERS`` names the one exception and pins it."""
    builder, wanted = _SHAPES[shape]
    path = builder(tmp_path, shape)
    expected = _random_access_outcomes(path)
    assert {name: expected[name] for name in wanted} == wanted
    with open_archive(path) as reader:
        assert _pass_outcomes(reader) == expected
    if shape.startswith(("zip", "tar")):
        with open_archive(NonSeekableBytesIO(path.read_bytes()), pipe=True) as reader:
            assert _pass_outcomes(reader) == {
                **expected,
                **_PIPE_DIFFERS.get(shape, {}),
            }
        with open_archive(io.BytesIO(path.read_bytes()), streaming=True) as reader:
            assert _pass_outcomes(reader) == expected
    else:
        with open_archive(path, streaming=True) as reader:
            assert _pass_outcomes(reader) == expected


@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "pipe"])
def test_zip_directory_data_digest_unverifiable_in_a_pass(
    tmp_path: Path, streaming: bool
) -> None:
    """A ZIP directory whose CRC-32 field is 0 over declared data reads unchecked, and
    says so with ``DIGEST_UNVERIFIABLE``, from a pass as from ``open()``. A pipe
    reports both codes once the central directory arrives, at the end of the pass."""
    data = _zip_directory_data(tmp_path, "zip-zero-crc").read_bytes()
    with open_archive(
        NonSeekableBytesIO(data) if streaming else io.BytesIO(data),
        pipe=streaming,
    ) as reader:
        read = {
            member.name: (member, stream.read() if stream is not None else None)
            for member, stream in reader.stream_members()
        }
    directory, data = read["d/"]
    assert data == b"hidden data!"
    assert directory.hashes == {}
    codes = {d.code for d in directory.diagnostics}
    assert DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED in codes
    assert DiagnosticCode.DIGEST_UNVERIFIABLE in codes


def test_zip_bit3_directory_from_a_pipe_says_it_has_no_stream(tmp_path: Path) -> None:
    """The pipe exception in ``_PIPE_DIFFERS`` is reported, not silent: the warning
    for a bit-3 directory read from a source that cannot seek says the pass yielded
    no stream, where every other read's warning says the pass delivers the bytes."""
    data = _zip_bit3_directory_data(tmp_path, "zip-bit3").read_bytes()
    messages = {}
    for label, source in (
        ("pipe", NonSeekableBytesIO(data)),
        ("seekable", io.BytesIO(data)),
    ):
        with open_archive(source, **open_mode(source, streaming=True)) as reader:
            list(reader.stream_members())
            [diag] = [
                d
                for d in reader.diagnostics.retained
                if d.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED
            ]
            messages[label] = diag.message
    assert (
        "stream_members() over a source that cannot seek yields no stream for it"
        in (messages["pipe"])
    )
    assert "open() and stream_members() deliver them" in messages["seekable"]
