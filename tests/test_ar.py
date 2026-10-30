"""The ar reader against archives written by GNU ar, bsdtar and llvm-ar
(``fixtures/ar/make-archives.sh``), read from a file and from a pipe."""

from __future__ import annotations

import ast
import gzip
import io
import lzma
import random
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import archivey
from archivey import (
    CorruptionError,
    MemberType,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
    detect_format,
    open_archive,
)
from archivey.formats import SequentialReader
from archivey.internal.backends import ar_reader
from archivey.internal.backends.ar_reader import ArReader

AR = archivey.ArchiveFormat.AR
DATA = Path(__file__).parent / "fixtures" / "ar"

LONG = "a-file-name-longer-than-sixteen.txt"
CONTENT = {
    "a.txt": b"hello\n",
    "odd.bin": random.Random(1).randbytes(1001),
    LONG: b"long\n",
}
NAMES = ["a.txt", "odd.bin", LONG, "sym.o"]
# archive: (dialect, whether it has a symbol table, the member mode)
# macOS ar pads each member with newlines so the next header starts on 8 bytes, and
# counts the padding in the member's size: llvm-ar and bsdtar extract it too.
ARCHIVES = {
    "gnu": ("gnu", True, 0o644),
    "bsd": ("bsd", False, 0o644),
    "darwin": ("bsd", True, 0o644),
}


class _Pipe(io.RawIOBase):
    """A source that cannot seek, as a pipe."""

    def __init__(self, data: bytes) -> None:
        self._inner = io.BytesIO(data)

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:  # type: ignore[override]
        return self._inner.readinto(b)


def _archive(tmp_path: Path, data: bytes, name: str = "t.a") -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _ar(*members: tuple[bytes, bytes]) -> bytes:
    """An ar archive of (name field, data) pairs, the name field written as given."""
    out = bytearray(b"!<arch>\n")
    for name, data in members:
        out += name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6)
        out += b"644".ljust(8) + str(len(data)).encode().ljust(10) + b"`\n" + data
        out += b"\n" * (len(data) & 1)
    return bytes(out)


@pytest.mark.parametrize("name", ARCHIVES)
def test_list_and_read(name: str) -> None:
    dialect, symbols, mode = ARCHIVES[name]
    with open_archive(DATA / f"{name}.a") as reader:
        assert reader.format == AR
        assert reader.info.format_version == dialect
        assert reader.info.extra["ar.symbol_table"] is symbols
        members = reader.members()
        assert [m.name for m in members] == NAMES
        for member in members:
            assert member.type is MemberType.FILE
            assert member.mode == mode
            assert member.uid == member.gid == 0
            assert member.modified is not None
            assert member.modified.timestamp() == 0
        for member_name in CONTENT:
            _check_content(name, reader.read(member_name), member_name)


def _expected(archive: str, name: str, data: bytes) -> bytes:
    """A member's content as archivey reads it from ``archive``: in darwin.a, padded
    with newlines so the next header starts on 8 bytes. llvm-ar stores each name in
    the data area padded with NULs, 36 bytes for the long one and 12 for the rest."""
    if archive != "darwin":
        return data
    stored_name = 36 if name == LONG else 12
    return data + b"\n" * (-(60 + stored_name + len(data)) % 8)


def _check_content(archive: str, got: bytes, name: str) -> None:
    assert got == _expected(archive, name, CONTENT[name]), (archive, name)


def test_the_dialects_hold_the_same_object() -> None:
    with open_archive(DATA / "gnu.a") as reader:
        obj = reader.read("sym.o")
    for name in ARCHIVES:
        with open_archive(DATA / f"{name}.a") as reader:
            assert reader.read("sym.o") == _expected(name, "sym.o", obj), name
    assert obj.startswith(b"\x7fELF")


@pytest.mark.parametrize("name", ARCHIVES)
def test_stream_from_a_pipe(name: str) -> None:
    data = (DATA / f"{name}.a").read_bytes()
    seen: dict[str, bytes] = {}
    with open_archive(_Pipe(data), streaming=True) as reader:
        assert reader.format == AR
        for member, stream in reader.stream_members():
            assert stream is not None
            seen[member.name] = stream.read()
    assert list(seen) == NAMES
    for member_name in CONTENT:
        _check_content(name, seen[member_name], member_name)


@pytest.mark.parametrize("name", ARCHIVES)
def test_streams_left_unread(name: str) -> None:
    """The walk resumes after a member whose stream was not read, or read in part."""
    data = (DATA / f"{name}.a").read_bytes()
    with open_archive(_Pipe(data), streaming=True) as reader:
        names = []
        for member, stream in reader.stream_members():
            names.append(member.name)
            if member.name == LONG:
                assert stream is not None
                assert stream.read(2) == b"lo"
    assert names == NAMES


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
@pytest.mark.parametrize("name", ARCHIVES)
def test_extract(tmp_path: Path, pipe: bool, name: str) -> None:
    """darwin.a's members extract with their padding, as llvm-ar and bsdtar write
    them."""
    path = DATA / f"{name}.a"
    source = _Pipe(path.read_bytes()) if pipe else path
    dest = tmp_path / "out"
    with open_archive(source, streaming=pipe) as reader:
        reader.extract_all(dest)
    for member_name in CONTENT:
        _check_content(name, (dest / member_name).read_bytes(), member_name)
    assert sorted(p.name for p in dest.iterdir()) == sorted(NAMES)


def test_detection() -> None:
    for name in ARCHIVES:
        info = detect_format(io.BytesIO((DATA / f"{name}.a").read_bytes()))
        assert info.format == AR, name
        assert info.detected_by == "magic"
        assert not info.from_plugin


@pytest.mark.parametrize(
    ("stream", "compress", "suffix"),
    [
        (archivey.StreamFormat.GZIP, lambda data: gzip.compress(data, mtime=0), ".gz"),
        (archivey.StreamFormat.XZ, lzma.compress, ".xz"),
    ],
    ids=["gz", "xz"],
)
@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_inside_a_compression_stream(
    tmp_path: Path,
    stream: archivey.StreamFormat,
    compress: Callable[[bytes], bytes],
    suffix: str,
    pipe: bool,
) -> None:
    """``.a.gz`` and ``.a.xz``: archivey decodes the stream, the reader sees ar."""
    data = compress((DATA / "gnu.a").read_bytes())
    path = tmp_path / f"t.a{suffix}"
    path.write_bytes(data)
    fmt = archivey.ArchiveFormat(AR.container, stream)
    assert detect_format(io.BytesIO(data)).format == fmt
    with open_archive(_Pipe(data) if pipe else path, streaming=pipe) as reader:
        assert reader.format == fmt
        seen = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
    assert list(seen) == NAMES
    for member_name in CONTENT:
        _check_content("gnu", seen[member_name], member_name)


@pytest.mark.parametrize("compressed", [False, True], ids=["plain", "gz"])
def test_seeks_inside_a_member(tmp_path: Path, compressed: bool) -> None:
    """With ``seekable_members=True`` a member stream seeks, plain and inside a
    compression stream (the shared seek matrix has no ar row)."""
    data = (DATA / "gnu.a").read_bytes()
    path = _archive(tmp_path, gzip.compress(data, mtime=0) if compressed else data)
    content = CONTENT["odd.bin"]
    with (
        open_archive(path, seekable_members=True) as reader,
        reader.open("odd.bin") as stream,
    ):
        assert stream.seekable()
        stream.seek(500)
        assert stream.read(100) == content[500:600]
        stream.seek(10)
        assert stream.read() == content[10:]


def test_a_thin_archive_is_refused() -> None:
    with pytest.raises(UnsupportedFeatureError, match="thin"):
        open_archive(DATA / "thin.a")


def test_windows_long_names_end_with_a_nul(tmp_path: Path) -> None:
    table = b"first-long-member-name.obj\0second-long-member-name.obj\0"
    data = _ar(
        (b"/", b"\0\0\0\0"),
        (b"/", b"\0\0\0\0\0\0"),
        (b"//", table),
        (b"/0", b"one"),
        (b"/27", b"two"),
        (b"short.obj/", b"three"),
    )
    with open_archive(_archive(tmp_path, data, "t.lib")) as reader:
        assert [m.name for m in reader.members()] == [
            "first-long-member-name.obj",
            "second-long-member-name.obj",
            "short.obj",
        ]
        assert reader.read("second-long-member-name.obj") == b"two"
        assert reader.info.extra["ar.symbol_table"] is True


def test_blank_fields(tmp_path: Path) -> None:
    raw = bytearray(_ar((b"x.txt/", b"data")))
    raw[8 + 16 : 8 + 48] = b" " * 32  # mtime, uid, gid, mode
    with open_archive(_archive(tmp_path, bytes(raw))) as reader:
        (member,) = reader.members()
        assert (member.modified, member.uid, member.gid, member.mode) == (None,) * 4
        assert reader.read("x.txt") == b"data"


def test_an_empty_archive(tmp_path: Path) -> None:
    with open_archive(_archive(tmp_path, b"!<arch>\n")) as reader:
        assert reader.members() == []
        assert reader.info.format_version is None


# Every symbol-table spelling, as a name field and, for the BSD ones, as a #1/ name in
# the data area (the only way the two longest fit).
_SYMBOL_TABLES = [
    ((b"/", b"\0" * 4), "gnu"),
    ((b"/SYM64/", b"\0" * 8), "gnu"),
    ((b"__.SYMDEF", b"\0" * 4), "bsd"),
    ((b"__.SYMDEF SORTED", b"\0" * 4), "bsd"),
    ((b"__.SYMDEF_64", b"\0" * 4), "bsd"),
] + [
    ((b"#1/%d" % len(name), name + b"\0" * 4), "bsd")
    for name in (
        b"__.SYMDEF",
        b"__.SYMDEF SORTED",
        b"__.SYMDEF_64",
        b"__.SYMDEF_64 SORTED",
    )
]


@pytest.mark.parametrize(
    ("table", "dialect"), _SYMBOL_TABLES, ids=[t[0].decode() for t, _ in _SYMBOL_TABLES]
)
def test_a_symbol_table_is_skipped_and_names_the_dialect(
    tmp_path: Path, table: tuple[bytes, bytes], dialect: str
) -> None:
    data = _ar(table, (b"x.txt" + (b"/" if dialect == "gnu" else b""), b"data"))
    with open_archive(_archive(tmp_path, data)) as reader:
        assert [m.name for m in reader.members()] == ["x.txt"]
        assert reader.info.extra["ar.symbol_table"] is True
        assert reader.info.format_version == dialect


def test_fields_padded_on_the_left(tmp_path: Path) -> None:
    """GNU ar reads numbers with strtol, which skips leading blanks."""
    header = b"x.txt/".ljust(16) + b"7".rjust(12) + b"0".rjust(6) + b"0".rjust(6)
    header += b"644".rjust(8) + b"4".rjust(10) + b"`\n"
    with open_archive(_archive(tmp_path, b"!<arch>\n" + header + b"data")) as reader:
        (member,) = reader.members()
        assert (member.size, member.mode) == (4, 0o644)
        assert member.modified is not None
        assert member.modified.timestamp() == 7
        assert reader.read("x.txt") == b"data"


def test_a_missing_last_pad_byte_is_harmless(tmp_path: Path) -> None:
    data = _ar((b"odd/", b"abc"))
    with open_archive(_archive(tmp_path, data[:-1])) as reader:
        assert reader.read("odd") == b"abc"


@pytest.mark.parametrize("pipe", [False, True], ids=["file", "pipe"])
def test_a_cut_archive_keeps_the_members_before_the_cut(
    tmp_path: Path, pipe: bool
) -> None:
    data = (DATA / "gnu.a").read_bytes()
    cut = data[: data.index(CONTENT["odd.bin"][:64]) + 500]
    source = _Pipe(cut) if pipe else _archive(tmp_path, cut)
    names = []
    with (
        open_archive(source, streaming=pipe) as reader,
        pytest.raises(TruncatedError),
    ):
        for member, stream in reader.stream_members():
            names.append(member.name)
            assert stream is not None
            stream.read()
    assert names == ["a.txt", "odd.bin"]


def test_damaged_headers(tmp_path: Path) -> None:
    good = _ar((b"x.txt/", b"data"))

    def opened(data: bytes) -> None:
        with open_archive(_archive(tmp_path, data), format=AR) as reader:
            reader.members()

    with pytest.raises(TruncatedError, match="empty"):
        opened(b"")
    with pytest.raises(TruncatedError, match="magic"):
        opened(b"!<ar")
    with pytest.raises(CorruptionError, match="No ar magic"):
        opened(b"!<arch>X" + good[8:])
    with pytest.raises(TruncatedError, match="header"):
        opened(good[:30])
    with pytest.raises(CorruptionError, match="No ar member header"):
        opened(good[:66] + b"xx" + good[68:])
    with pytest.raises(CorruptionError, match="size field"):
        opened(good[:56] + b"x" + good[57:])
    with pytest.raises(CorruptionError, match="long-name table"):
        opened(_ar((b"/0", b"data")))
    with pytest.raises(CorruptionError, match="past the"):
        opened(_ar((b"//", b"name/\n"), (b"/40", b"data")))
    with pytest.raises(CorruptionError, match="second long-name table"):
        opened(_ar((b"//", b"a/\n"), (b"//", b"b/\n")))
    with pytest.raises(CorruptionError, match="a name of 99 bytes"):
        opened(_ar((b"#1/99", b"short")))
    with pytest.raises(CorruptionError, match="the name length is blank"):
        opened(_ar((b"#1/", b"short")))
    with pytest.raises(CorruptionError, match="mode field"):
        opened(_ar((b"x/", b"data")).replace(b"644 ", b"648 ", 1))
    with pytest.raises(CorruptionError, match="size field"):
        opened(_ar((b"x/", b"data")).replace(b"4         `", b"-4        `", 1))
    with pytest.raises(CorruptionError, match="no name"):
        opened(_ar((b"", b"data")))


def test_the_name_table_is_charged_to_max_metadata_bytes(tmp_path: Path) -> None:
    data = _ar((b"//", b"a-long-member-name.txt/\n"), (b"/0", b"data"))
    path = _archive(tmp_path, data)

    def config(limit: int | None) -> archivey.ArchiveyConfig:
        limits = archivey.ListingLimits(max_metadata_bytes=limit)
        return archivey.ArchiveyConfig(listing_limits=limits)

    with pytest.raises(ResourceLimitError, match="max_metadata_bytes=10"):
        open_archive(path, config=config(10))
    for limit in (None, 1024):
        with open_archive(path, config=config(limit)) as reader:
            assert reader.read("a-long-member-name.txt") == b"data"


def test_a_time_past_the_datetime_range(tmp_path: Path) -> None:
    raw = bytearray(_ar((b"x/", b"data")))
    raw[8 + 16 : 8 + 28] = b"999999999999"
    with open_archive(_archive(tmp_path, bytes(raw))) as reader:
        assert reader.members()[0].modified is None


def _imported_names(path: Path) -> Iterator[tuple[str, str]]:
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            yield from ((alias.name, "") for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield from ((node.module, alias.name) for alias in node.names)


def test_the_reader_uses_only_public_archivey() -> None:
    """Written as a format added from outside would be: every archivey name it imports
    is public, apart from the call that registers it as a built-in."""
    for module, name in _imported_names(Path(ar_reader.__file__)):
        if module.split(".")[0] != "archivey":
            continue
        if module == "archivey.internal.format_adapter":
            assert name == "register_builtin_format"
        elif module == "archivey.formats":
            assert name in archivey.formats.__all__, name
        else:
            assert name in archivey.__all__, (module, name)


def test_the_reader_is_a_sequential_reader() -> None:
    assert issubclass(ArReader, SequentialReader)
