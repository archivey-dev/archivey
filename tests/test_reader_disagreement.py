"""MEMBER_READERS_DISAGREE and MEMBER_NAME_DUPLICATE: shapes real archives have,
which archivey reads as the format's own tool does and other readers read otherwise.

Both codes are advisory (out of ``ARCHIVE_INTEGRITY_CODES``, logged at INFO), so the
default and ``STRICT`` policies read the archive and ``PEDANTIC`` refuses it. The TAR
cases follow tar-minefield K01, K02, N10, N11, S04, S06, S07, S08, S09 and S10.
The ZIP and CPIO cases carry two of them to other formats: a NUL in a name (N14's
shape) and a ZIP directory marked by its attributes alone (K01's, reversed).
"""

from __future__ import annotations

import io
import logging
import pathlib
import stat
import zipfile

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    DiagnosticCode,
    DiagnosticPolicy,
    MemberType,
    open_archive,
)
from archivey.diagnostics import NameDuplicateContext, ReaderDisagreementContext
from archivey.exceptions import DiagnosticRaisedError
from tests.streams_util import NonSeekableBytesIO
from tests.tar_build import END, block, data, field, octal, pax

GNU_MAGIC = b"ustar  \x00"


def _file(name: bytes, payload: bytes = b"ab", **kwargs: object) -> bytes:
    return block(name, size=len(payload), **kwargs) + data(payload)  # type: ignore[arg-type]


def _star_mark(h: bytearray) -> None:
    h[508:512] = b"tar\x00"


def _reported(archive: bytes, *, streaming: bool = False) -> list[tuple[str, str, str]]:
    """(member name, code, shape or earlier member id) for each of the two codes."""
    source = NonSeekableBytesIO(archive) if streaming else io.BytesIO(archive)
    found = []
    with open_archive(source, streaming=streaming) as ar:
        members = (
            [m for m, _ in ar.stream_members()] if streaming else list(ar.members())
        )
        for member in members:
            for d in member.diagnostics:
                if isinstance(d.context, ReaderDisagreementContext):
                    found.append((member.name, str(d.code), d.context.shape))
                elif isinstance(d.context, NameDuplicateContext):
                    found.append(
                        (member.name, str(d.code), str(d.context.earlier_member_id))
                    )
    return found


_DISAGREE = str(DiagnosticCode.MEMBER_READERS_DISAGREE)
_DUPLICATE = str(DiagnosticCode.MEMBER_NAME_DUPLICATE)

# (archive, what is reported)
_TAR_SHAPES = {
    # K01: a v7-style directory, a regular file named d/.
    "file named as directory": (
        block(b"d/", typeflag=b"0") + END,
        [("d/", _DISAGREE, "file_named_as_directory")],
    ),
    # K02: bgen writes a link name on regular files.
    "link name on file": (
        _file(b"a", linkname=b"elsewhere") + END,
        [("a", _DISAGREE, "link_name_on_file")],
    ),
    # N10: star's mark, and a prefix past star's 131 bytes.
    "star prefix": (
        _file(b"a", prefix=b"p" * 140, patch=_star_mark) + END,
        [("p" * 140 + "/a", _DISAGREE, "star_prefix")],
    ),
    # N11: GNU tar's incremental atime where ustar keeps the prefix.
    "gnu prefix bytes": (
        _file(b"a", magic=GNU_MAGIC, patch=field(345, 357, octal(1_700_000_000, 12)))
        + END,
        [("a", _DISAGREE, "gnu_prefix_bytes")],
    ),
    # S06: a hard link to a symlink.
    "hardlink to symlink": (
        _file(b"f")
        + block(b"s", typeflag=b"2", linkname=b"f")
        + block(b"h", typeflag=b"1", linkname=b"s")
        + END,
        [("h", _DISAGREE, "hardlink_to_symlink")],
    ),
    # S07 and S09: the same file twice.
    "duplicate file": (
        _file(b"a", b"one") + _file(b"a", b"two") + END,
        [("a", _DUPLICATE, "0")],
    ),
    # S04: a hard link to itself repeats the name of the file it shadows.
    "hardlink to itself": (
        _file(b"a") + block(b"a", typeflag=b"1", linkname=b"a") + END,
        [("a", _DUPLICATE, "0")],
    ),
    # S10: a symlink, then a file of that name.
    "symlink then file": (
        block(b"a", typeflag=b"2", linkname=b"t") + _file(b"a") + END,
        [("a", _DUPLICATE, "0")],
    ),
    # S08: a file, then a directory of that name.
    "file then directory": (
        _file(b"a") + block(b"a/", typeflag=b"5") + END,
        [("a/", _DUPLICATE, "0")],
    ),
}


@pytest.mark.parametrize("label", list(_TAR_SHAPES))
@pytest.mark.parametrize("streaming", [False, True])
def test_tar_shape_is_reported(label: str, streaming: bool) -> None:
    archive, expected = _TAR_SHAPES[label]
    assert _reported(archive, streaming=streaming) == expected


_TAR_ORDINARY = {
    # A ustar prefix of the full 155 bytes, with no star mark.
    "long ustar prefix": _file(b"a", prefix=b"p" * 155) + END,
    # star's mark with a prefix that fits star's 131 bytes.
    "short star prefix": _file(b"a", prefix=b"p" * 100, patch=_star_mark) + END,
    # A PAX path overrides the star prefix, so it names nothing.
    "star prefix under a pax path": (
        pax({"path": "named"}) + _file(b"a", prefix=b"p" * 140, patch=_star_mark) + END
    ),
    # An ordinary old GNU header has NULs at 345.
    "gnu header": _file(b"a", magic=GNU_MAGIC) + END,
    "hardlink to file": _file(b"f") + block(b"h", typeflag=b"1", linkname=b"f") + END,
    "symlink to symlink": (
        block(b"s", typeflag=b"2", linkname=b"f")
        + block(b"t", typeflag=b"2", linkname=b"s")
        + END
    ),
    # Every reader makes one directory of a directory listed twice.
    "directory twice": (
        block(b"d/", typeflag=b"5") + block(b"d/", typeflag=b"5") + END
    ),
    # A link name on a symlink is its target.
    "symlink": block(b"s", typeflag=b"2", linkname=b"f") + END,
}


@pytest.mark.parametrize("label", list(_TAR_ORDINARY))
def test_ordinary_tar_reports_neither(label: str) -> None:
    assert _reported(_TAR_ORDINARY[label]) == []


def _policy(policy: DiagnosticPolicy) -> ArchiveyConfig:
    return ArchiveyConfig(diagnostic_policy=policy)


@pytest.mark.parametrize("label", list(_TAR_SHAPES))
def test_strict_reads_the_shape_and_pedantic_refuses_it(label: str) -> None:
    archive, _ = _TAR_SHAPES[label]
    with open_archive(
        io.BytesIO(archive),
        format=ArchiveFormat.TAR,
        config=_policy(DiagnosticPolicy.STRICT),
    ) as ar:
        ar.members()
    with (
        open_archive(
            io.BytesIO(archive),
            format=ArchiveFormat.TAR,
            config=_policy(DiagnosticPolicy.PEDANTIC),
        ) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        ar.members()


def test_a_caller_can_refuse_only_these_two_codes() -> None:
    archive, _ = _TAR_SHAPES["duplicate file"]
    policy = DiagnosticPolicy(
        raise_on=[
            DiagnosticCode.MEMBER_NAME_DUPLICATE,
            DiagnosticCode.MEMBER_READERS_DISAGREE,
        ]
    )
    with (
        open_archive(io.BytesIO(archive), config=_policy(policy)) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        ar.members()


def test_both_codes_log_at_info(caplog: pytest.LogCaptureFixture) -> None:
    archive = (
        _file(b"a", linkname=b"x") + _file(b"a") + END
    )  # link name on a file, then a duplicate
    caplog.set_level(logging.DEBUG, logger="archivey")
    with open_archive(io.BytesIO(archive)) as ar:
        ar.members()
    levels = {
        record.diagnostic_code: record.levelno  # type: ignore[attr-defined]
        for record in caplog.records
        if hasattr(record, "diagnostic_code")
    }
    assert levels == {
        DiagnosticCode.MEMBER_READERS_DISAGREE: logging.INFO,
        DiagnosticCode.MEMBER_NAME_DUPLICATE: logging.INFO,
    }


def test_a_zip_with_a_name_twice_is_reported() -> None:
    """Not TAR only: unzip extracts the later copy, and a reader that keeps the
    first gives another file."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("a.txt", b"one")
        with pytest.warns(UserWarning, match="Duplicate name"):
            zf.writestr("a.txt", b"two")
    assert _reported(buffer.getvalue()) == [("a.txt", _DUPLICATE, "0")]


def test_the_report_names_both_members() -> None:
    archive, _ = _TAR_SHAPES["symlink then file"]
    with open_archive(io.BytesIO(archive)) as ar:
        _, later = ar.members()
    (diagnostic,) = later.diagnostics
    assert diagnostic.context == NameDuplicateContext(
        archive_name=None,
        member_name="a",
        member_id=1,
        earlier_member_id=0,
        earlier_type="symlink",
        member_type="file",
    )


def test_a_pax_linkpath_on_a_file_is_reported() -> None:
    """The PAX spelling of K02: a PAX writer stores a link name in linkpath."""
    archive = pax({"linkpath": "elsewhere"}) + _file(b"a") + END
    assert _reported(archive) == [("a", _DISAGREE, "link_name_on_file")]


def _zip_with_local_names(central: tuple[str, str], local: tuple[str, str]) -> bytes:
    """Two members, named ``central`` in the directory and ``local`` in their
    local headers (each pair of names the same length)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(central[0], b"one")
        if central[0] == central[1]:
            with pytest.warns(UserWarning, match="Duplicate name"):
                zf.writestr(central[1], b"two")
        else:
            zf.writestr(central[1], b"two")
    data = bytearray(buffer.getvalue())
    at = 0
    for name in local:
        at = data.index(b"PK\x03\x04", at)
        length = int.from_bytes(data[at + 26 : at + 28], "little")
        assert length == len(name)
        data[at + 30 : at + 30 + length] = name.encode()
        at += 30
    return bytes(data)


@pytest.mark.parametrize(
    ("central", "local", "expected"),
    [
        # The directory's names collide: reported however the ZIP is read.
        (("a.txt", "a.txt"), ("a.txt", "b.txt"), [("a.txt", _DUPLICATE, "0")]),
        # Only the local names collide: the listing has no duplicate.
        (("a.txt", "b.txt"), ("a.txt", "a.txt"), []),
    ],
)
@pytest.mark.parametrize("pipe", [False, True])
def test_a_zip_duplicate_is_decided_on_the_directory_names(
    central: tuple[str, str],
    local: tuple[str, str],
    expected: list[tuple[str, str, str]],
    pipe: bool,
) -> None:
    """A ZIP read from a pipe names its members from the directory, read last, so
    it compares those names, as a file read does."""
    archive = _zip_with_local_names(central, local)
    assert _reported(archive, streaming=pipe) == expected


def _zip_with_nul_name() -> bytes:
    """One member, its stored name ``a\\0b.txt`` in both the directory and the local
    header (``zipfile`` cannot write a NUL itself)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("aaaaaaa", b"one")
    data = bytearray(buffer.getvalue())
    for signature, fixed in ((b"PK\x03\x04", 30), (b"PK\x01\x02", 46)):
        at = data.index(signature)
        data[at + fixed : at + fixed + 7] = b"a\x00b.txt"
    return bytes(data)


def _newc(name: bytes, payload: bytes, mode: int = 0o100644, ino: int = 1) -> bytes:
    fields = [ino, mode, 0, 0, 1, 0, len(payload), 0, 0, 0, 0, len(name) + 1, 0]
    header = b"070701" + b"".join(b"%08X" % value for value in fields) + name + b"\0"
    header += b"\0" * (-len(header) % 4)
    return header + payload + b"\0" * (-len(payload) % 4)


@pytest.mark.parametrize("streaming", [False, True])
def test_a_nul_in_a_zip_name_is_reported(streaming: bool) -> None:
    """unzip writes the name up to the NUL and 7-Zip refuses the archive."""
    assert _reported(_zip_with_nul_name(), streaming=streaming) == [
        ("a\x00b.txt", _DISAGREE, "nul_in_name")
    ]


def test_a_nul_in_a_cpio_name_is_reported() -> None:
    archive = _newc(b"a\x00b.txt", b"one") + _newc(b"TRAILER!!!", b"", 0, 0)
    assert _reported(archive) == [("a\x00b.txt", _DISAGREE, "nul_in_name")]


def test_a_member_named_with_a_nul_is_not_extracted(tmp_path: pathlib.Path) -> None:
    with open_archive(io.BytesIO(_zip_with_nul_name())) as ar:
        ar.extract_all(tmp_path)
    assert list(tmp_path.iterdir()) == []


_DOS = 0  # "version made by" host: MS-DOS / FAT
_UNIX = 3


def _zip_entry(
    name: str, *, host: int, external_attr: int, payload: bytes = b""
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        info = zipfile.ZipInfo(name)
        info.create_system = host
        info.external_attr = external_attr
        zf.writestr(info, payload)
    return buffer.getvalue()


_DIRECTORY_BY_ATTRIBUTE = {
    "dos directory bit": _zip_entry("d", host=_DOS, external_attr=0x10),
    "unix directory mode": _zip_entry(
        "d", host=_UNIX, external_attr=(stat.S_IFDIR | 0o755) << 16
    ),
}


@pytest.mark.parametrize("label", list(_DIRECTORY_BY_ATTRIBUTE))
@pytest.mark.parametrize("streaming", [False, True])
def test_a_zip_directory_by_attribute_is_a_directory(
    label: str, streaming: bool, tmp_path: pathlib.Path
) -> None:
    """APPNOTE 4.4.15 marks the type in the attributes; 7-Zip and libarchive make a
    directory, unzip a file."""
    archive = _DIRECTORY_BY_ATTRIBUTE[label]
    assert _reported(archive, streaming=streaming) == [
        ("d/", _DISAGREE, "directory_attribute_without_slash")
    ]
    source = NonSeekableBytesIO(archive) if streaming else io.BytesIO(archive)
    with open_archive(source, streaming=streaming) as ar:
        ar.extract_all(tmp_path)
    assert (tmp_path / "d").is_dir()


def test_a_zip_directory_by_attribute_with_data_drops_it() -> None:
    """7-Zip makes a directory of it too; the bytes are a directory's data."""
    archive = _zip_entry("d", host=_DOS, external_attr=0x10, payload=b"data")
    with open_archive(io.BytesIO(archive)) as ar:
        (member,) = ar.members()
    assert member.type is MemberType.DIRECTORY
    assert [d.code for d in member.diagnostics] == [
        DiagnosticCode.MEMBER_READERS_DISAGREE,
        DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED,
    ]


@pytest.mark.parametrize(
    ("host", "external_attr"),
    [
        # The DOS bit means nothing from a Unix creator, whose mode is a file's.
        (_UNIX, (stat.S_IFREG | 0o644) << 16 | 0x10),
        # Nor from a host whose low word is not a DOS attribute word.
        (7, 0x10),
        # A DOS creator without the bit.
        (_DOS, 0x20),
    ],
)
def test_other_zip_attributes_leave_a_file(host: int, external_attr: int) -> None:
    archive = _zip_entry("d", host=host, external_attr=external_attr)
    with open_archive(io.BytesIO(archive)) as ar:
        (member,) = ar.members()
    assert member.type is MemberType.FILE
    assert _reported(archive) == []
