"""MEMBER_READERS_DISAGREE and MEMBER_NAME_DUPLICATE: shapes real archives have,
which archivey reads as the format's own tool does and other readers read otherwise.

Both codes are advisory (out of ``ARCHIVE_INTEGRITY_CODES``, logged at INFO), so the
default and ``STRICT`` policies read the archive and ``PEDANTIC`` refuses it. The TAR
cases follow tar-minefield K01, K02, N10, N11, S04, S06, S07, S09 and S10.
"""

from __future__ import annotations

import io
import logging
import zipfile

import pytest

from archivey import (
    ArchiveFormat,
    ArchiveyConfig,
    DiagnosticCode,
    DiagnosticPolicy,
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
