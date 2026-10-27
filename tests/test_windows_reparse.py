"""Windows reparse points in ZIP and 7z: symlinks, junctions, and what is lost.

The archives under `tests/fixtures/external/junction/` were built by 7-Zip on a Windows
runner, because a junction cannot be created anywhere else; the temporary CI job that
made them is gone, and `tests/fixtures/external/README.md` carries its exact recipe
along with the full finding. What those archives contain is the point of these tests,
so the assertions here are deliberately about the *measured* shapes rather than the
ones the format would allow.
"""

from __future__ import annotations

import os
import struct
import subprocess
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any, BinaryIO

import pytest

from archivey import ExtractionStatus, OverwritePolicy, open_archive
from archivey.config import ArchiveyConfig
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticPolicy,
)
from archivey.exceptions import (
    CorruptionError,
    FilterRejectionError,
    LinkTargetNotFoundError,
)
from archivey.internal.backends import directory_reader, rar_parser
from archivey.internal.backends.rar_parser import RarArchive, RarMemberInfo
from archivey.internal.backends.rar_reader import _rar_member_extra_and_link
from archivey.internal.backends.zip_reader import ZipReader
from archivey.internal.base_reader import MAX_LINK_TARGET_BYTES
from archivey.internal.windows_reparse import (
    FILE_ATTRIBUTE_REPARSE_POINT,
    IO_REPARSE_TAG_MOUNT_POINT,
    IO_REPARSE_TAG_SYMLINK,
    parse_reparse_data,
)
from archivey.types import ArchiveMember, MemberType, OnError
from tests.conftest import requires_binary
from tests.extract_util import open_and_extract
from tests.memory_util import traced_peak
from tests.test_link_target_portability import _7z_number

_JUNCTION_DIR = Path(__file__).parent / "fixtures" / "external" / "junction"

# FILE_ATTRIBUTE_DIRECTORY, for the directory-shaped entries built below.
_FILE_ATTRIBUTE_DIRECTORY = 0x10


def _reparse_buffer(tag: int, substitute: str, print_name: str) -> bytes:
    """Assemble a REPARSE_DATA_BUFFER the way Windows lays one out."""
    subst = substitute.encode("utf-16-le") + b"\0\0"
    printed = print_name.encode("utf-16-le") + b"\0\0"
    # Offsets are into PathBuffer; lengths exclude the terminating NUL.
    names = struct.pack("<HHHH", 0, len(subst) - 2, len(subst), len(printed) - 2)
    flags = struct.pack("<I", 0) if tag == IO_REPARSE_TAG_SYMLINK else b""
    body = names + flags + subst + printed
    return struct.pack("<IHH", tag, len(body), 0) + body


# --------------------------------------------------------------------------------
# The parser
# --------------------------------------------------------------------------------


def test_junction_buffer_yields_the_target_and_the_flag() -> None:
    parsed = parse_reparse_data(
        _reparse_buffer(
            IO_REPARSE_TAG_MOUNT_POINT, "\\??\\C:\\tree\\target", "C:\\tree\\target"
        )
    )
    assert parsed is not None
    assert parsed.is_junction
    assert parsed.target == "C:/tree/target"


def test_symlink_buffer_is_not_a_junction() -> None:
    parsed = parse_reparse_data(
        _reparse_buffer(
            IO_REPARSE_TAG_SYMLINK, "target\\payload.txt", "target\\payload.txt"
        )
    )
    assert parsed is not None
    assert not parsed.is_junction
    assert parsed.target == "target/payload.txt"


def test_junction_falls_back_to_the_substitute_name_without_its_nt_prefix() -> None:
    """A junction written with no PrintName still resolves, minus the `\\??\\`."""
    parsed = parse_reparse_data(
        _reparse_buffer(IO_REPARSE_TAG_MOUNT_POINT, "\\??\\C:\\tree\\target", "")
    )
    assert parsed is not None
    assert parsed.target == "C:/tree/target"


@pytest.mark.parametrize(
    "substitute",
    [
        pytest.param("\\??\\UNC\\server\\share\\dir", id="object-manager"),
        pytest.param("\\\\?\\UNC\\server\\share\\dir", id="win32-long-path"),
        pytest.param("\\??\\unc\\server\\share\\dir", id="lower-case"),
    ],
)
def test_unc_substitute_name_keeps_its_leading_double_slash(substitute: str) -> None:
    """`\\??\\UNC\\server\\share` names `\\\\server\\share`, not a relative `UNC/...`."""
    parsed = parse_reparse_data(_reparse_buffer(IO_REPARSE_TAG_SYMLINK, substitute, ""))
    assert parsed is not None
    assert parsed.target == "//server/share/dir"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"", id="empty"),
        pytest.param(b"hello\r\n", id="ordinary-file-content"),
        pytest.param(
            struct.pack("<IHH", IO_REPARSE_TAG_MOUNT_POINT, 0, 0), id="header-only"
        ),
        # A real tag, but one whose payload is not a link target at all.
        pytest.param(
            struct.pack("<IHH", 0x80000013, 4, 0) + b"\0\0\0\0", id="dedup-tag"
        ),
    ],
)
def test_non_link_buffers_are_declined(data: bytes) -> None:
    """Anything that is not a link buffer parses to None rather than a made-up path."""
    assert parse_reparse_data(data) is None


@pytest.mark.parametrize("which", ["substitute", "print"])
def test_an_odd_name_length_is_declined_rather_than_raising(which: str) -> None:
    """A name length is a byte count over UTF-16 code units, so an odd one is malformed.

    `errors=` does not cover a trailing half code unit — `surrogatepass` raises on it
    too — so an unguarded decode sends `UnicodeDecodeError` out of `members()` from a
    crafted archive. `test_truncated_payload_does_not_raise` cannot reach this: cutting
    the buffer leaves the declared offsets out of bounds, so the bounds guard
    short-circuits before any decode runs. The length has to be odd *and* in bounds.
    """
    subst_length, print_length = (3, 0) if which == "substitute" else (0, 3)
    body = struct.pack("<HHHH", 0, subst_length, 0, print_length) + b"abcd"
    data = struct.pack("<IHH", IO_REPARSE_TAG_MOUNT_POINT, len(body), 0) + body
    parsed = parse_reparse_data(data)
    assert parsed is not None
    assert parsed.is_junction
    # Declined, not decoded to the even prefix: reporting half a path as the target
    # would be inventing one.
    assert parsed.target == ""


def test_truncated_payload_does_not_raise() -> None:
    whole = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "target", "target")
    # 8-byte header, 8 bytes of name offsets, 4 bytes of symlink flags, then the
    # substitute name (12 bytes and a NUL) from byte 20 of the payload.
    names_end = 16
    substitute_end = 16 + 4 + len("target".encode("utf-16-le"))
    # No prefix raises. One too short for the name offsets is declined; one that holds
    # them but not a whole name parses to a link with no target; past that, the
    # substitute name is in bounds and is the target.
    for cut in range(len(whole) + 1):
        parsed = parse_reparse_data(whole[:cut])
        if cut < names_end:
            assert parsed is None, cut
        elif cut < substitute_end:
            assert parsed is not None, cut
            assert parsed.target == "", cut
        else:
            assert parsed is not None, cut
            assert parsed.target == "target", cut


@pytest.mark.parametrize("declared", [0, 7])
def test_a_declared_payload_shorter_than_the_name_offsets_is_declined(
    declared: int,
) -> None:
    """The declared length is trusted when the bytes are there, so it can decline alone."""
    data = struct.pack("<IHH", IO_REPARSE_TAG_SYMLINK, declared, 0) + b"\0" * 64
    assert parse_reparse_data(data) is None


# --------------------------------------------------------------------------------
# The real archives
# --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture",
    [
        pytest.param("junction_7zip_snl.zip", id="zip"),
        pytest.param("junction_7zip_snl.7z", id="7z"),
    ],
)
def test_7zip_file_symlink_reports_its_real_target(fixture: str) -> None:
    """The buffer is decoded, not handed back as if it were a path.

    Before this was parsed, 7z reported those 92 bytes UTF-8-decoded as the link
    target and ZIP did not notice the member was a link at all.
    """
    with open_archive(_JUNCTION_DIR / fixture) as archive:
        member = next(m for m in archive.members() if m.name == "tree/symlink_file")
        assert member.type is MemberType.SYMLINK
        assert member.link_target == "target/payload.txt"
        assert not member.is_junction


@pytest.mark.parametrize(
    "fixture",
    [
        pytest.param("junction_7zip_snl.zip", id="zip"),
        pytest.param("junction_7zip_snl.7z", id="7z"),
    ],
)
@pytest.mark.parametrize("name", ["tree/junction_dir", "tree/symlink_dir"])
def test_7zip_directory_reparse_point_is_a_link_with_no_target(
    fixture: str, name: str
) -> None:
    """7-Zip stores no data for a directory reparse point, so the target is gone.

    A junction is always a directory reparse point, which is why `is_junction` is
    False here for the junction as well as the symlink: the tag that would have
    separated them is inside the data that was never written. Both backends agree,
    and the member keeps the trailing slash off its name.
    """
    with open_archive(_JUNCTION_DIR / fixture) as archive:
        member = next(m for m in archive.members() if m.name == name)
        assert member.type is MemberType.SYMLINK
        assert member.link_target is None
        assert not member.is_junction


@pytest.mark.parametrize(
    "fixture",
    [
        pytest.param("junction_7zip_snl.zip", id="zip"),
        pytest.param("junction_7zip_snl.7z", id="7z"),
    ],
)
@pytest.mark.parametrize(
    "name", ["tree/junction_dir", "tree/symlink_dir", "tree/symlink_file"]
)
def test_every_reparse_member_is_flagged_as_one(fixture: str, name: str) -> None:
    """The weaker fact the archive does record, in both formats.

    `is_junction` needs the tag out of the member's data and 7-Zip does not store it for
    a directory reparse point, so it is unset on all three. The attribute bit is in the
    header, so this one is set on all three — including the file symlink, which is what
    lets a caller tell a Windows symlink from a POSIX one.
    """
    with open_archive(_JUNCTION_DIR / fixture) as archive:
        member = next(m for m in archive.members() if m.name == name)
        assert member.is_reparse_point
        assert member.extra["is_reparse_point"] is True
        assert not member.is_junction


def test_a_plain_unix_symlink_is_not_flagged(tmp_path: Path) -> None:
    """The flag says "Windows", so a POSIX symlink must not carry it."""
    archive = tmp_path / "unix_symlink.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 3  # UNIX
        info.external_attr = (0o120777 << 16) | 0x20
        zf.writestr(info, b"target.txt")
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.type is MemberType.SYMLINK
        assert member.link_target == "target.txt"
        assert not member.is_reparse_point
        assert "is_reparse_point" not in member.extra


def test_a_reinterpreted_member_keeps_the_reparse_flag(tmp_path: Path) -> None:
    """The flag records what the archive said, so it survives the re-typing.

    `is_reparse_point` is deliberately not gated on the member's type: the archive did
    flag this entry, and that is the explanation for why it looked odd.
    """
    archive = tmp_path / "odd_reparse.zip"
    _zip_with_reparse_member(
        archive,
        name="tree/weird",
        attributes=0x20 | FILE_ATTRIBUTE_REPARSE_POINT,
        data=b"not a reparse buffer",
    )
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.type is MemberType.FILE
        assert member.is_reparse_point


# --------------------------------------------------------------------------------
# The other two formats that state the kind
# --------------------------------------------------------------------------------


def _rar_info(redirect_type: int) -> SimpleNamespace:
    """The fields `_rar_member_extra_and_link` reads, and nothing else."""
    return SimpleNamespace(
        file_redir=(redirect_type, 0, "target"),
        is_file_version_history=lambda: False,
        is_file_copy=lambda: redirect_type == 5,
        file_version=None,
        extract_version=None,
        file_encryption=None,
        crc32=None,
        blake2sp_hash=None,
        host_os=None,
        ctime=None,
    )


@pytest.mark.parametrize(
    ("redirect_type", "reparse", "junction"),
    [
        pytest.param(1, False, False, id="unix-symlink"),
        pytest.param(2, True, False, id="windows-symlink"),
        pytest.param(3, True, True, id="windows-junction"),
    ],
)
def test_rar_flags_both_windows_redirect_types(
    redirect_type: int, reparse: bool, junction: bool
) -> None:
    """RAR names the kind in a header field, so it can flag while listing.

    A RAR5 Windows symlink (redirect type 2) is a reparse point just as much as a
    junction (type 3); only a Unix symlink (type 1) is not. Flagging the junction alone
    would make the key mean something narrower in RAR than in ZIP and 7z.
    """
    extra, _ = _rar_member_extra_and_link(_rar_info(redirect_type))  # type: ignore[arg-type]
    assert extra.get("is_reparse_point", False) is reparse
    assert extra.get("is_junction", False) is junction


@pytest.mark.parametrize("os_name", ["nt", "posix"])
def test_a_scanned_symlink_is_a_reparse_point_only_on_windows(
    monkeypatch: pytest.MonkeyPatch, os_name: str
) -> None:
    """Scanning a live tree: on Windows a symlink *is* a reparse point, there being no
    other kind; elsewhere it is a POSIX one and the key does not apply."""
    monkeypatch.setattr(directory_reader.os, "name", os_name)
    extra = directory_reader._link_extra(MemberType.SYMLINK, is_junction=False)
    assert extra.get("is_reparse_point", False) is (os_name == "nt")
    file_extra = directory_reader._link_extra(MemberType.FILE, is_junction=False)
    assert "is_reparse_point" not in file_extra


# --------------------------------------------------------------------------------
# Extracting a link the archive gave no target for
# --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture",
    [
        pytest.param("junction_7zip_snl.zip", id="zip"),
        pytest.param("junction_7zip_snl.7z", id="7z"),
    ],
)
@pytest.mark.parametrize(
    "streaming",
    [pytest.param(False, id="seekable"), pytest.param(True, id="streaming")],
)
def test_a_targetless_link_is_skipped_and_the_rest_extracts(
    fixture: str, streaming: bool, tmp_path: Path
) -> None:
    """Nothing can be written for it, and nothing here went wrong, so it is not a failure.

    The library default is `OnError.STOP`, so treating it as a per-member failure aborted
    the whole archive on the first such member — and 7-Zip writes one for every directory
    symlink and every junction.

    Both read modes, because for a while only one of them did this. The fact that
    settles these two members — the writer stored no data, so it recorded no target —
    is in the header, and nothing about it needs a seek. But the decision used to be
    taken in the link-target hook, which a streaming pass does not run until EOF, long
    after extraction has chosen what to do with the member. So exactly the member this
    whole feature exists for raised instead, and the default aborted the archive.

    The file symlink in this tree does carry its target, in the member's own data, and
    extraction reads it once the link is accepted, so it is written in both modes.
    """
    with open_archive(_JUNCTION_DIR / fixture, streaming=streaming) as opened:
        report = opened.extract_all(tmp_path, on_error=OnError.STOP)
    by_name = {r.member.name: r for r in report.results}
    for name in ("tree/junction_dir", "tree/symlink_dir"):
        assert by_name[name].status is ExtractionStatus.LINK_TARGET_UNAVAILABLE
        assert by_name[name].path is None
        assert by_name[name].error is None
    assert by_name["tree/regular.txt"].status is ExtractionStatus.EXTRACTED
    assert (tmp_path / "tree" / "regular.txt").read_bytes() == b"plain\r\n"
    # Nothing was left behind at the skipped paths.
    assert not (tmp_path / "tree" / "junction_dir").exists()
    assert by_name["tree/symlink_file"].status is ExtractionStatus.EXTRACTED


def test_an_omission_only_the_data_shows_is_reported_in_both_modes(
    tmp_path: Path,
) -> None:
    """A buffer that names nothing records no target just as surely as no buffer at all.

    It is in the member's *data*, which a streaming pass reads only at EOF on its own.
    Extraction reads an accepted link's data before writing it, so the streaming read
    reaches the same answer as the seekable one instead of failing the member.
    """
    archive = tmp_path / "nameless_symlink.zip"
    _zip_with_reparse_member(
        archive,
        name="nameless_link",
        attributes=FILE_ATTRIBUTE_REPARSE_POINT,
        data=struct.pack("<IHH", IO_REPARSE_TAG_SYMLINK, 12, 0)
        + struct.pack("<HHHHI", 0, 0, 0, 0, 0),
    )
    with open_archive(archive) as opened:
        (result,) = opened.extract_all(tmp_path / "seekable").results
    assert result.status is ExtractionStatus.LINK_TARGET_UNAVAILABLE
    assert result.error is None

    with open_archive(archive, streaming=True) as opened:
        (result,) = opened.extract_all(tmp_path / "streaming").results
    assert result.status is ExtractionStatus.LINK_TARGET_UNAVAILABLE
    assert result.error is None


def test_skipping_a_targetless_link_does_not_replace_what_is_there(
    tmp_path: Path,
) -> None:
    """A member that is not going to be written must not unlink an existing destination.

    `OverwritePolicy.REPLACE` unlinks first and creates fresh, so checking the target
    after overwrite resolution would destroy the entry on behalf of a member that then
    writes nothing.
    """
    dest = tmp_path / "out"
    (dest / "tree").mkdir(parents=True)
    existing = dest / "tree" / "junction_dir"
    existing.write_text("previously here", encoding="utf-8")
    results = open_and_extract(
        _JUNCTION_DIR / "junction_7zip_snl.zip",
        dest,
        overwrite=OverwritePolicy.REPLACE,
    )
    by_name = {r.member.name: r for r in results}
    assert (
        by_name["tree/junction_dir"].status is ExtractionStatus.LINK_TARGET_UNAVAILABLE
    )
    assert existing.read_text(encoding="utf-8") == "previously here"


def test_the_junction_and_the_symlink_are_indistinguishable_on_disk() -> None:
    """The finding itself, asserted so it cannot regress unnoticed.

    If a later 7-Zip starts storing the reparse data for directory reparse points,
    this fails and the junction flag becomes reachable from a real archive.
    """
    with zipfile.ZipFile(_JUNCTION_DIR / "junction_7zip_snl.zip") as zf:
        junction = zf.getinfo("tree/junction_dir/")
        symlink = zf.getinfo("tree/symlink_dir/")
    assert junction.external_attr == symlink.external_attr
    assert junction.external_attr & FILE_ATTRIBUTE_REPARSE_POINT
    assert junction.file_size == symlink.file_size == 0


# --------------------------------------------------------------------------------
# A writer that does keep the data
# --------------------------------------------------------------------------------


@pytest.mark.parametrize("read_link_targets", [True, False])
@pytest.mark.parametrize("streaming", [False, True], ids=["random-access", "streaming"])
def test_extraction_writes_a_reparse_member_that_is_not_a_link_as_a_file(
    tmp_path: Path, read_link_targets: bool, streaming: bool
) -> None:
    """Reading the target during extraction re-types the member; it is written as that.

    Under `read_link_targets=False` the read that shows the data is no reparse buffer
    comes after the pass yielded the member as a link, with no data stream. Random
    access opens the member then. A forward-only pass is already past the content, so
    that case fails loudly; it must never become a clean `LINK_TARGET_UNAVAILABLE`
    with nothing written. Under the default a streaming pass reads the target when it
    reaches the member, so it yields the member as a file and writes it.
    """
    archive = tmp_path / "odd_reparse.zip"
    _zip_with_reparse_member(
        archive,
        name="weird",
        attributes=0x20 | FILE_ATTRIBUTE_REPARSE_POINT,
        data=b"not a reparse buffer",
    )
    dest = tmp_path / "out"
    config = ArchiveyConfig(read_link_targets=read_link_targets)
    with open_archive(archive, streaming=streaming, config=config) as opened:
        (result,) = opened.extract_all(dest, on_error=OnError.CONTINUE).results
    assert result.member.type is MemberType.FILE
    if streaming and not read_link_targets:
        assert result.status is ExtractionStatus.FAILED
        assert "streaming pass" in str(result.error)
        assert not os.path.lexists(dest / "weird")
    else:
        assert result.status is ExtractionStatus.EXTRACTED
        assert (dest / "weird").read_bytes() == b"not a reparse buffer"


def test_a_filter_sees_a_reparse_member_again_once_it_is_known_to_be_a_file(
    tmp_path: Path,
) -> None:
    """The filter decided on a link that does not exist, so it decides again."""
    archive = tmp_path / "odd_reparse.zip"
    _zip_with_reparse_member(
        archive,
        name="weird",
        attributes=0x20 | FILE_ATTRIBUTE_REPARSE_POINT,
        data=b"not a reparse buffer",
    )
    seen: list[MemberType] = []

    def recording(member: ArchiveMember) -> ArchiveMember:
        seen.append(member.type)
        return member

    config = ArchiveyConfig(read_link_targets=False)
    with open_archive(archive, config=config) as opened:
        opened.extract_all(tmp_path / "out", filter=recording)
    assert seen == [MemberType.SYMLINK, MemberType.FILE]


def _zip_with_reparse_member(
    path: Path, *, name: str, attributes: int, data: bytes
) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        info = zipfile.ZipInfo(name)
        info.create_system = 0  # FAT, as every Windows writer of these uses
        info.external_attr = attributes
        zf.writestr(info, data)


def _sevenzip_with_members(path: Path, entries: list[tuple[str, int, bytes]]) -> None:
    """A 7z archive with one Copy folder holding each ``(name, attributes, data)``.

    No 7z writer stores a reparse-flagged file with arbitrary data, so the header is
    built here. Every entry needs data: a zero-size entry would need an empty-stream
    property, which this builder does not write.
    """
    num = _7z_number
    datas = [data for _, _, data in entries]
    packed = b"".join(datas)
    substreams = b"\x08\x0d" + num(len(datas))
    if len(datas) > 1:
        substreams += b"\x09" + b"".join(num(len(d)) for d in datas[:-1])
    substreams += b"\x0a\x01" + b"".join(
        struct.pack("<I", zlib.crc32(d)) for d in datas
    )
    substreams += b"\x00"
    streams = (
        b"\x04\x06"  # MainStreamsInfo, PackInfo
        + num(0)
        + num(1)
        + b"\x09"
        + num(len(packed))
        + b"\x00"
        + b"\x07\x0b"
        + num(1)
        + b"\x00"
        + b"\x01\x01\x00"  # one coder, a one-byte id, Copy
        + b"\x0c"
        + num(len(packed))
        + b"\x00"
        + substreams
        + b"\x00"
    )
    name_data = b"\x00" + b"".join(
        name.encode("utf-16-le") + b"\0\0" for name, _, _ in entries
    )
    attr_data = b"\x01\x00" + b"".join(
        struct.pack("<I", attributes) for _, attributes, _ in entries
    )
    files = (
        b"\x05"
        + num(len(entries))
        + b"\x11"
        + num(len(name_data))
        + name_data
        + b"\x15"
        + num(len(attr_data))
        + attr_data
        + b"\x00"
    )
    header = b"\x01" + streams + files + b"\x00"
    start = struct.pack("<QQI", len(packed), len(header), zlib.crc32(header))
    signature = b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", zlib.crc32(start))
    path.write_bytes(signature + start + packed + header)


# The pass reads 9 bytes of such a member to decide its type: the 8 header bytes, plus
# one, because the payload length it declares counts only for a link tag. This content
# is much longer than those 9 bytes, so the rest of the member takes many reads of the
# folder decoder after them.
_LONG_CONTENT = bytes(range(256)) * 300


def _read_whole_member(member: ArchiveMember, stream: BinaryIO) -> bytes:
    """Read ``stream`` with one ``read(member.size)``, which is full-count.

    The next read must give ``b""``: a short return is terminal, never "ask again".
    """
    assert member.size is not None
    data = stream.read(member.size)
    assert stream.read(1) == b""
    return data


# A symlink buffer followed by bytes past its declared end: not a link buffer either.
_PADDED_LINK = (
    _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "C:\\target", "C:\\target") + b"P" * 100
)


@pytest.mark.parametrize("read_link_targets", [True, False])
@pytest.mark.parametrize("streaming", [False, True], ids=["random-access", "streaming"])
@pytest.mark.parametrize(
    "content",
    [b"not a reparse buffer", _LONG_CONTENT, _PADDED_LINK],
    ids=["short", "long", "padded-link"],
)
def test_a_7z_pass_yields_a_non_link_reparse_member_with_its_content(
    tmp_path: Path, read_link_targets: bool, streaming: bool, content: bytes
) -> None:
    """`stream_members()` agrees with `members()` on such a member, in both modes.

    A 7z pass reads a link member's data as it passes it. It used to keep those bytes
    and decide only at the end, so the member was yielded as a link with no stream and
    re-typed to a file afterwards: its content was dropped with no error. The pass now
    decides when it reaches the member and yields its whole content. The member after
    it in the same folder still reads correctly.

    Under `read_link_targets=False` the pass reads no link data on its own, so it
    yields the member as listing types it, a link with no stream, and nothing re-types
    it later.
    """
    archive = tmp_path / "odd_reparse.7z"
    _sevenzip_with_members(
        archive,
        [
            ("tree/weird", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, content),
            ("tree/after.txt", 0x20, b"next member"),
        ],
    )
    config = ArchiveyConfig(read_link_targets=read_link_targets)
    with open_archive(archive, streaming=streaming, config=config) as opened:
        yielded = [
            (
                member,
                member.type,
                None if stream is None else _read_whole_member(member, stream),
            )
            for member, stream in opened.stream_members()
        ]
    seen = [(member.name, member_type, data) for member, member_type, data in yielded]
    if read_link_targets:
        assert seen == [
            ("tree/weird", MemberType.FILE, content),
            ("tree/after.txt", MemberType.FILE, b"next member"),
        ]
    else:
        assert seen == [
            ("tree/weird", MemberType.SYMLINK, None),
            ("tree/after.txt", MemberType.FILE, b"next member"),
        ]
    # The pass does not re-type a member after yielding it.
    assert [member.type for member, _, _ in yielded] == [t for _, t, _ in seen]


@pytest.mark.parametrize("read_link_targets", [True, False])
@pytest.mark.parametrize("streaming", [False, True], ids=["random-access", "streaming"])
@pytest.mark.parametrize(
    "content", [_LONG_CONTENT, _PADDED_LINK], ids=["long", "padded-link"]
)
def test_a_zip_pass_yields_a_non_link_reparse_member_with_its_content(
    tmp_path: Path, read_link_targets: bool, streaming: bool, content: bytes
) -> None:
    """The ZIP pass types such a member when it reaches it, as the 7z pass does.

    A streaming pass used to yield it as a link with no stream and re-type it to a
    file when the pass ended, so its content never reached the caller. Under
    `read_link_targets=False` nothing reads link data on its own, and the member stays
    the link listing typed it as.
    """
    archive = tmp_path / "odd_reparse.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, attributes, data in [
            ("tree/weird", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, content),
            ("tree/after.txt", 0x20, b"next member"),
        ]:
            info = zipfile.ZipInfo(name)
            info.create_system = 0
            info.external_attr = attributes
            zf.writestr(info, data)
    config = ArchiveyConfig(read_link_targets=read_link_targets)
    with open_archive(archive, streaming=streaming, config=config) as opened:
        yielded = [
            (
                member,
                member.type,
                None if stream is None else _read_whole_member(member, stream),
            )
            for member, stream in opened.stream_members()
        ]
    seen = [(member.name, member_type, data) for member, member_type, data in yielded]
    if read_link_targets:
        assert seen == [
            ("tree/weird", MemberType.FILE, content),
            ("tree/after.txt", MemberType.FILE, b"next member"),
        ]
    else:
        assert seen == [
            ("tree/weird", MemberType.SYMLINK, None),
            ("tree/after.txt", MemberType.FILE, b"next member"),
        ]
    assert [member.type for member, _, _ in yielded] == [t for _, t, _ in seen]


@pytest.mark.parametrize("streaming", [False, True], ids=["random-access", "streaming"])
def test_a_7z_pass_extracts_a_non_link_reparse_member_as_a_file(
    tmp_path: Path, streaming: bool
) -> None:
    """The pass knows the member is a file before extraction sees it, so a streaming
    pass writes it too instead of failing it as one it cannot go back for."""
    archive = tmp_path / "odd_reparse.7z"
    _sevenzip_with_members(
        archive, [("weird", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, _LONG_CONTENT)]
    )
    dest = tmp_path / "out"
    with open_archive(archive, streaming=streaming) as opened:
        (result,) = opened.extract_all(dest).results
    assert result.member.type is MemberType.FILE
    assert result.status is ExtractionStatus.EXTRACTED
    assert (dest / "weird").read_bytes() == _LONG_CONTENT


def test_a_7z_pass_verifies_the_content_it_yields_for_a_reparse_member(
    tmp_path: Path,
) -> None:
    """The bytes read to decide the type are given back, not read again, so the CRC
    still has to cover them: damage in them fails the read of the yielded stream.

    Those bytes are the 8 header bytes plus one. The damaged byte is the ninth: the
    tag is still not a link tag, so the member is still re-typed to a file.
    """
    archive = tmp_path / "odd_reparse.7z"
    _sevenzip_with_members(
        archive, [("weird", 0x20 | FILE_ATTRIBUTE_REPARSE_POINT, _LONG_CONTENT)]
    )
    data = bytearray(archive.read_bytes())
    # The packed data starts after the 32-byte start header; the folder is stored.
    data[32 + 8] ^= 0xFF
    archive.write_bytes(bytes(data))
    with open_archive(archive, streaming=True) as opened:
        for member, stream in opened.stream_members():
            assert member.type is MemberType.FILE
            assert member.size is not None
            assert stream is not None
            with pytest.raises(CorruptionError):
                stream.read(member.size)


def test_a_7z_pass_still_reads_a_real_link_buffer_as_a_link(tmp_path: Path) -> None:
    """Deciding at the member leaves a reparse buffer that names a target a link."""
    archive = tmp_path / "link.7z"
    _sevenzip_with_members(
        archive,
        [
            (
                "link",
                0x20 | FILE_ATTRIBUTE_REPARSE_POINT,
                _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "C:\\target", "C:\\target"),
            ),
            ("after.txt", 0x20, b"next member"),
        ],
    )
    with open_archive(archive, streaming=True) as opened:
        yielded = [
            (member, member.type, None if stream is None else stream.read())
            for member, stream in opened.stream_members()
        ]
    link = yielded[0][0]
    seen = [(member.name, member_type, data) for member, member_type, data in yielded]
    assert seen == [
        ("link", MemberType.SYMLINK, None),
        ("after.txt", MemberType.FILE, b"next member"),
    ]
    assert link.link_target == "C:/target"


def test_a_unc_symlink_is_blocked_at_extraction(tmp_path: Path) -> None:
    """A UNC target leaves the destination on Windows, so extraction refuses the link
    on every OS.

    Before the parser kept the leading `//`, the same buffer produced the relative
    `UNC/server/share/dir`, which resolves inside the destination and was created.
    """
    archive = tmp_path / "unc_link.zip"
    _zip_with_reparse_member(
        archive,
        name="link",
        attributes=FILE_ATTRIBUTE_REPARSE_POINT,
        data=_reparse_buffer(
            IO_REPARSE_TAG_SYMLINK, "\\??\\UNC\\server\\share\\dir", ""
        ),
    )
    dest = tmp_path / "out"
    with open_archive(archive) as opened:
        (result,) = opened.extract_all(dest, on_error=OnError.CONTINUE).results
    assert result.member.link_target == "//server/share/dir"
    assert result.status is ExtractionStatus.BLOCKED
    assert isinstance(result.error, FilterRejectionError)
    assert result.error.message == "Symlink target is a Windows drive or UNC path"
    assert not (dest / "link").is_symlink()


def test_a_stored_junction_buffer_sets_the_flag(tmp_path: Path) -> None:
    """No Windows tool writes this, but the format allows it and the reader handles it.

    This is the one path on which the `archive-data-model` junction promise can be
    kept, so it is worth having even though the probe found nothing that produces it.
    """
    archive = tmp_path / "stored_junction.zip"
    _zip_with_reparse_member(
        archive,
        name="tree/junction_dir/",
        attributes=_FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
        data=_reparse_buffer(
            IO_REPARSE_TAG_MOUNT_POINT, "\\??\\C:\\tree\\target", "C:\\tree\\target"
        ),
    )
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.name == "tree/junction_dir"
        assert member.type is MemberType.SYMLINK
        assert member.is_junction
        assert member.extra["is_junction"] is True
        assert member.is_reparse_point
        assert member.link_target == "C:/tree/target"


def test_a_nameless_junction_buffer_still_sets_the_flag(tmp_path: Path) -> None:
    """The tag is the buffer's first field, so it survives a buffer that names nothing.

    Dropping the flag because a *different* field was empty would throw away the one
    thing the tag established, and `ReparsePoint.target` documents `""` as a legitimate
    value.
    """
    archive = tmp_path / "nameless_junction.zip"
    _zip_with_reparse_member(
        archive,
        name="tree/junction_dir/",
        attributes=_FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
        data=struct.pack("<IHH", IO_REPARSE_TAG_MOUNT_POINT, 8, 0)
        + struct.pack("<HHHH", 0, 0, 0, 0),
    )
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.type is MemberType.SYMLINK
        assert member.is_junction
        assert member.link_target is None


def test_a_reparse_member_whose_data_is_not_a_link_keeps_its_content(
    tmp_path: Path,
) -> None:
    """The bit is a candidate; the data decides, and here the data is a file's content.

    Windows sets `FILE_ATTRIBUTE_REPARSE_POINT` for deduplication stubs, cloud
    placeholders and WSL entries too. Typing on the bit alone would make this member a
    link with no target, so `open()` on it would raise and its real content — the one
    thing we know is in the archive — would be unreachable.
    """
    archive = tmp_path / "odd_reparse.zip"
    _zip_with_reparse_member(
        archive,
        name="tree/weird",
        attributes=0x20 | FILE_ATTRIBUTE_REPARSE_POINT,
        data=b"not a reparse buffer",
    )
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.type is MemberType.FILE
        assert member.link_target is None
        assert not member.is_junction
        with opened.open(member) as stream:
            assert stream.read() == b"not a reparse buffer"


def test_a_reparse_target_over_the_link_cap_is_refused(tmp_path: Path) -> None:
    """A reparse buffer's target is held to the cap every data-stored target is.

    The cap is on the target, measured in UTF-8 like the other formats' targets, not
    on the UTF-16 buffer, whose byte count is roughly twice the path's.
    """
    at_cap = "a" * MAX_LINK_TARGET_BYTES
    over = "b" * (MAX_LINK_TARGET_BYTES + 1)
    archive = tmp_path / "long_reparse.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, target in (("at_cap", at_cap), ("over", over)):
            info = zipfile.ZipInfo(name)
            info.create_system = 0
            info.external_attr = 0x20 | FILE_ATTRIBUTE_REPARSE_POINT
            zf.writestr(info, _reparse_buffer(IO_REPARSE_TAG_SYMLINK, target, target))
    with open_archive(archive) as opened:
        by_name = {m.name: m for m in opened.members()}
        assert by_name["at_cap"].link_target == at_cap
        assert by_name["over"].type is MemberType.SYMLINK
        assert by_name["over"].link_target is None
        assert _unavailable_reasons(opened) == ["target_too_long"]


# Deflated zeros: a ~64 KiB member that decodes to 64 MiB.
_LARGE_CONTENT = b"\0" * (64 << 20)


def test_a_large_non_link_reparse_member_keeps_all_its_content(
    tmp_path: Path,
) -> None:
    """Deciding reads the buffer's header only, and the content is not cut to it.

    A deduplication stub or cloud placeholder keeps its whole file in this data, so the
    decision must not refuse it for its size, must not decode the whole of it while
    listing, and its diagnostic must name the size the archive declares rather than the
    few bytes the decision read.
    """
    archive = tmp_path / "big_odd_reparse.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("tree/weird")
        info.create_system = 0
        info.external_attr = 0x20 | FILE_ATTRIBUTE_REPARSE_POINT
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, _LARGE_CONTENT)
    with open_archive(archive) as opened:
        assert traced_peak(opened.members) < 8 << 20
        (member,) = opened.members()
        assert member.type is MemberType.FILE
        with opened.open(member) as stream:
            assert stream.read() == _LARGE_CONTENT
        (reported,) = [
            d
            for d in opened.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
        assert f"{len(_LARGE_CONTENT)} bytes" in reported.message


def test_a_link_buffer_is_read_only_as_far_as_it_declares(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The flag that routes a member here is the archive's to set, so the read is sized
    by the buffer's own header, not by the most a buffer could ever declare (65 543
    bytes, which across many members is hundreds of times the archive).

    The read stops one byte past the buffer. A byte there means the data is not that
    buffer, so the member is a file, and the rest is decoded only when it is read.
    """
    delivered: list[int] = []
    original_open = ZipReader._open_member

    def counting_open(self: ZipReader, member: ArchiveMember) -> object:
        stream = original_open(self, member)
        original_read = stream.read

        def read(n: int = -1) -> bytes:
            data = original_read(n)
            delivered.append(len(data))
            return data

        stream.read = read  # type: ignore[method-assign]
        return stream

    monkeypatch.setattr(ZipReader, "_open_member", counting_open)

    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "C:\\target", "C:\\target")
    archive = tmp_path / "padded_reparse.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("link")
        info.create_system = 0
        info.external_attr = 0x20 | FILE_ATTRIBUTE_REPARSE_POINT
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, buffer + _LARGE_CONTENT)
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.type is MemberType.FILE
        assert member.link_target is None
    assert sum(delivered) == len(buffer) + 1


def _padded_link_member(*, damaged: bool) -> tuple[bytes, bytes]:
    """A symlink buffer with bytes after its declared end.

    Returns ``(data, stored)``: the data to build the archive from, and the bytes to
    store in it, which are the same data unless ``damaged``. The damaged bytes change
    one byte in the PrintName, which is the target read first."""
    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "C:\\target", "C:\\target")
    data = buffer + b"P" * 100
    at = data.rindex("target".encode("utf-16-le"))
    changed = bytearray(data)
    changed[at] ^= 1
    return data, bytes(changed) if damaged else data


@pytest.mark.parametrize("damaged", [False, True], ids=["intact", "damaged"])
@pytest.mark.parametrize("fmt", ["zip", "7z"])
def test_data_longer_than_its_link_buffer_is_a_file_with_a_checked_crc(
    tmp_path: Path, fmt: str, damaged: bool
) -> None:
    """Data that runs on past the buffer its header declares is not a link buffer:
    Windows returns exactly the header and ReparseDataLength bytes. The member is a
    file holding that data, and reading it checks its CRC.

    It used to list as a link to the buffer's target with the data read only to one
    byte past the buffer, so the CRC was never checked: a damaged target listed as
    ``uarget`` with no error.
    """
    data, stored = _padded_link_member(damaged=damaged)
    archive = tmp_path / f"padded.{fmt}"
    attributes = 0x20 | FILE_ATTRIBUTE_REPARSE_POINT
    if fmt == "zip":
        _zip_with_reparse_member(archive, name="link", attributes=attributes, data=data)
        raw = archive.read_bytes()
        archive.write_bytes(raw.replace(data, stored))
    else:
        _sevenzip_with_members(archive, [("link", attributes, data)])
        raw = archive.read_bytes()
        archive.write_bytes(raw.replace(data, stored))
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.type is MemberType.FILE
        assert member.link_target is None
        assert _unavailable_reasons(opened) == ["reparse_data_unrecognized"]
        if damaged:
            with pytest.raises(CorruptionError), opened.open(member) as stream:
                stream.read()
        else:
            with opened.open(member) as stream:
                assert stream.read() == data


def test_a_directory_shaped_reparse_point_with_odd_data_stays_a_link(
    tmp_path: Path,
) -> None:
    """Re-typing pays for a file and not for a directory, so it is declined here.

    The re-type exists to keep unrecognised data reachable, and only a FILE's content is
    reachable — `open()` refuses a DIRECTORY. Re-typing this member would have promised
    "that data as its content" while making the content unreadable, and the entry has
    already lost the trailing slash that made it a directory, because the ZIP backend
    suppresses that rename's diagnostic for a link stored with the directory convention.
    Leaving it a targetless link keeps what the archive actually said.
    """
    archive = tmp_path / "odd_directory_reparse.zip"
    _zip_with_reparse_member(
        archive,
        name="tree/weird/",
        attributes=_FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
        data=b"not a reparse buffer",
    )
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.type is MemberType.SYMLINK
        # The name that normalization produced is right for what the member stayed:
        # a link carries no trailing slash. Re-typing was what made it inconsistent.
        assert member.name == "tree/weird"
        assert member.link_target is None
        assert not member.is_junction
        assert _unavailable_reasons(opened) == ["reparse_data_unrecognized"]


def test_a_directory_shaped_link_buffer_with_data_past_it_stays_a_targetless_link(
    tmp_path: Path,
) -> None:
    """Data that runs on past its buffer is no link buffer, and a directory-shaped
    member is not re-typed to carry it (as above): it stays a link with no target, and
    extraction writes nothing for it. The buffer's target used to be listed and
    written."""
    data = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "tree\\target", "tree\\target")
    archive = tmp_path / "padded_directory_reparse.zip"
    _zip_with_reparse_member(
        archive,
        name="linkdir/",
        attributes=_FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
        data=data + b"P" * 40,
    )
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.type is MemberType.SYMLINK
        assert member.link_target is None
        assert _unavailable_reasons(opened) == ["reparse_data_unrecognized"]
        report = opened.extract_all(tmp_path / "out")
    (result,) = report.results
    assert result.status is ExtractionStatus.LINK_TARGET_UNAVAILABLE
    assert not (tmp_path / "out" / "linkdir").exists()
    assert not (tmp_path / "out" / "linkdir").is_symlink()


def test_a_directory_reparse_point_with_no_data_stays_a_link(tmp_path: Path) -> None:
    """The other side of the rule: nothing to reinterpret, so the link type stands."""
    archive = tmp_path / "empty_reparse.zip"
    _zip_with_reparse_member(
        archive,
        name="tree/junction_dir/",
        attributes=_FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
        data=b"",
    )
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.type is MemberType.SYMLINK
        assert member.link_target is None
        assert _unavailable_reasons(opened) == ["reparse_data_absent"]


def test_the_reparse_bit_is_read_only_from_a_dos_creator(tmp_path: Path) -> None:
    """`0x400` in the low word is a Win32 attribute only for a DOS/Windows creator.

    Every other creator puts its own platform's bits there, so the bit is a
    coincidence. A directory is the case where that is observable: it carries no data
    for the parser to overrule the type with, so a widened creator test turns an
    ordinary Macintosh-created directory into a link with no target — and drops its
    trailing slash on the way.
    """
    archive = tmp_path / "mac_creator.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        info = zipfile.ZipInfo("tree/plain/")
        info.create_system = 7  # MACINTOSH
        info.external_attr = _FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT
        zf.writestr(info, b"")
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.type is MemberType.DIRECTORY
        assert member.name == "tree/plain/"
        assert member.link_target is None


@pytest.mark.parametrize(
    "fixture",
    [
        pytest.param("junction_7zip_snl.zip", id="zip"),
        pytest.param("junction_7zip_snl.7z", id="7z"),
    ],
)
@pytest.mark.parametrize(
    "streaming",
    [pytest.param(False, id="seekable"), pytest.param(True, id="streaming")],
)
def test_a_missing_target_is_reported_once_per_member(
    fixture: str, streaming: bool, tmp_path: Path
) -> None:
    """Looking for a target that is not there must not repeat on every access.

    Nothing the lookup can learn changes between two calls, so a second one only
    re-reads the member and emits the same diagnostic again — counting one targetless
    link as two in `DiagnosticSummary.counts`.

    Once per member is not once per pass. `extract_all` lists an indexed archive twice —
    once for the progress totals and the selector, once to drive the extraction — so a
    member the header alone settles is settled twice, and ZIP builds a fresh
    `ArchiveMember` object for it each time while 7z hands back the same one. The report
    therefore has to be recognised as one already made, and then follow the member onto
    whichever object this pass produced: the caller holds that one, and an empty
    `member.diagnostics` on the member it can see is no report at all.

    Parametrised over both read modes because the two backends lose it in different
    places. A progressive 7z pass streams off its cached member list, registering
    nothing and finalizing nothing, so anything that waits for either is never delivered
    at all — the archive comes back with two anomalies and a silent diagnostics channel,
    and a strict policy stops refusing it.
    """
    code = DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
    with open_archive(_JUNCTION_DIR / fixture) as archive:
        members = archive.members()
        assert archive.diagnostics.counts.get(code) == 2
        for member in members:
            if member.type is MemberType.SYMLINK and member.link_target is None:
                with pytest.raises(LinkTargetNotFoundError):
                    archive.open(member)
        assert archive.diagnostics.counts.get(code) == 2

    with open_archive(_JUNCTION_DIR / fixture, streaming=streaming) as archive:
        report = archive.extract_all(tmp_path, on_error=OnError.CONTINUE)
        assert archive.diagnostics.counts.get(code) == 2
        # The archive's own omissions, which is narrower than "no target came back":
        # in streaming `tree/symlink_file` also arrives without one, because its target
        # is in data this pass has gone past, and that stays a per-member failure.
        targetless = [
            result.member
            for result in report.results
            if result.status is ExtractionStatus.LINK_TARGET_UNAVAILABLE
        ]
        assert len(targetless) == 2
        for member in targetless:
            reported = [d for d in member.diagnostics if d.code is code]
            assert len(reported) == 1
            # The member the report names is the member the caller is holding.
            assert reported[0].context.member_id == member._member_id


@pytest.mark.parametrize(
    "config",
    [
        pytest.param(
            ArchiveyConfig(
                diagnostic_policy=DiagnosticPolicy(
                    ignore={DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE}
                )
            ),
            id="ignored",
        ),
        pytest.param(
            ArchiveyConfig(max_retained_diagnostic_references=0), id="nothing-retained"
        ),
    ],
)
@pytest.mark.parametrize(
    "streaming",
    [pytest.param(False, id="seekable"), pytest.param(True, id="streaming")],
)
def test_a_missing_target_is_counted_once_even_when_it_attaches_to_nothing(
    config: ArchiveyConfig, streaming: bool, tmp_path: Path
) -> None:
    """The report a caller never receives still has to be remembered as made.

    Recognising a repeat sighting by the report the first one left on the member works
    only while there is a report to find. Under an `IGNORE` disposition, and once the
    retention budget is spent, the emission attaches nothing — and then a ZIP, which
    builds a fresh `ArchiveMember` for each listing pass, has nothing to recognise and
    reports the same targetless link a second time.

    `IGNORE` is the configuration that can least afford it: retention, the log and the
    callback are all switched off, so `DiagnosticSummary.counts` is the only channel
    left and an inflated count is the whole signal. The budget case needs no unusual
    configuration at all — past the default 256 references every further targetless link
    in a ZIP would count twice.
    """
    code = DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
    with open_archive(
        _JUNCTION_DIR / "junction_7zip_snl.zip", streaming=streaming, config=config
    ) as archive:
        archive.extract_all(tmp_path, on_error=OnError.CONTINUE)
        assert archive.diagnostics.counts.get(code) == 2


def test_a_tar_symlink_spelled_as_a_directory_is_still_reported(tmp_path: Path) -> None:
    """The ZIP suppression must not reach a backend that never asked for it.

    A ZIP directory reparse point is *stored* with the directory convention's trailing
    slash, so dropping it is the format's spelling rather than an author override. A TAR
    `SYMTYPE` entry named `link/` is an anomaly, and `MEMBER_NAME_NORMALIZED` is an
    archive-integrity code, so suppressing it there would silently stop a strict policy
    refusing that archive.
    """
    archive = tmp_path / "slashed_symlink.tar"
    with tarfile.open(archive, "w") as tf:
        info = tarfile.TarInfo("link/")
        info.type = tarfile.SYMTYPE
        info.linkname = "target.txt"
        tf.addfile(info)
    with open_archive(archive) as opened:
        (member,) = opened.members()
        assert member.name == "link"
        assert opened.diagnostics.counts.get(DiagnosticCode.MEMBER_NAME_NORMALIZED) == 1


# --------------------------------------------------------------------------------
# A link whose target the archive will not yield
# --------------------------------------------------------------------------------


def _encrypted_archive_with_a_symlink(tmp_path: Path, archive_type: str) -> Path:
    """Write an archive holding one symlink whose target is encrypted with its data.

    The symlink is left dangling on purpose: a regular file alongside it would be
    encrypted too, so extracting without the password would fail on that member and
    never reach the link.
    """
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "link.txt").symlink_to("absent.txt")
    archive = tmp_path / ("enc.zip" if archive_type == "-tzip" else "enc.7z")
    subprocess.run(
        ["7z", "a", archive_type, "-snl", "-pSECRET", "-y", str(archive), "tree"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    return archive


@requires_binary("7z")
@pytest.mark.parametrize(
    "archive_type", [pytest.param("-tzip", id="zip"), pytest.param("-t7z", id="7z")]
)
def test_an_encrypted_link_says_why_its_target_is_missing(
    tmp_path: Path, archive_type: str
) -> None:
    """A link whose target is unreadable has to say so, whatever put it out of reach.

    `ExtractionStatus.LINK_TARGET_UNAVAILABLE` carries no reason of its own — it says only that nothing
    was written — so the reason travels on the diagnostics channel instead, and
    `SYMLINK_TARGET_UNAVAILABLE` being in `ARCHIVE_INTEGRITY_CODES` is what lets a
    strict policy refuse such an archive outright. A backend that returns quietly turns
    an unreadable link into a silent omission, which is the one outcome
    `safe-extraction` rules out. Listing without a password still has to work, so this
    is a diagnostic and not a raise.

    Extraction is a different question, and this archive *does* record the target: it
    is locked, not missing. So the link fails the way the encrypted file beside it
    does, rather than being dropped from the output under a status that reports
    nothing wrong. Both assertions are here because the diagnostic and the extraction
    outcome answer to different rules, and the earlier version of this test conflated
    them.
    """
    archive = _encrypted_archive_with_a_symlink(tmp_path, archive_type)
    with open_archive(archive) as opened:
        (link,) = [m for m in opened.members() if m.type is MemberType.SYMLINK]
        assert link.link_target is None
        assert _unavailable_reasons(opened) == ["password_required"]

    dest = tmp_path / "out"
    results = open_and_extract(archive, dest, on_error=OnError.CONTINUE)
    by_name = {r.member.name: r for r in results}
    assert by_name["tree/link.txt"].status is ExtractionStatus.FAILED
    assert isinstance(by_name["tree/link.txt"].error, LinkTargetNotFoundError)
    assert not (dest / "tree" / "link.txt").exists()

    # The library default aborts the extraction, as it does for the encrypted file.
    with pytest.raises(LinkTargetNotFoundError):
        open_and_extract(archive, tmp_path / "stop")


@pytest.mark.parametrize(
    ("fields", "value", "reason", "in_archive"),
    [
        pytest.param(
            ("is_encrypted",), True, "target_data_encrypted", True, id="encrypted"
        ),
        pytest.param(
            ("split_after",), True, "target_data_split_across_volumes", True, id="split"
        ),
        # The parts of a target split across volumes are merged into one member
        # before this branch sees it, so once the final part is in, neither split
        # flag is left set. Merged, it records its parts and they are joined (the
        # next test); ``spanned_volumes`` with no recorded parts is a target this
        # read cannot reach.
        pytest.param(
            ("spanned_volumes",),
            True,
            "target_data_split_across_volumes",
            True,
            id="spanned",
        ),
        pytest.param(
            ("compress_type",), 0x33, "target_data_compressed", True, id="compressed"
        ),
        # Both sizes: only one of them zero is a damaged header, not an empty target.
        pytest.param(
            ("file_size", "compress_size"), 0, "no_target_data", False, id="empty"
        ),
    ],
)
def test_a_rar4_link_whose_data_is_out_of_reach_says_why(
    monkeypatch: pytest.MonkeyPatch,
    fields: tuple[str, ...],
    value: object,
    reason: str,
    in_archive: bool,
) -> None:
    """The RAR4 fallthrough was the third silent path, and it has four causes.

    RAR3/4 store a symlink's target as the member's own data, so the reader reads it
    straight out of the archive — and declines to when that data is encrypted, split
    across volumes, compressed rather than stored, or simply absent. Every one of those
    left `link_target` unset and said nothing, so `safe-extraction`'s promise that a
    skipped link is always explained held for ZIP and for nothing else.

    Patching the parsed header rather than writing four archives is deliberate: RAR 7
    dropped `-ma4`, so the writer this repo installs cannot produce a RAR4 archive at
    all, and each flag here is the only thing that would differ between this fixture
    and the archive a RAR4 writer would emit. The branch reads nothing else off the
    member. Only the symlinks are touched, so the rest of the listing stays honest.

    The fields are patched after the header walk, not in the member's constructor:
    the walk skips a FILE header's data by its parsed ``compress_size``, so zeroing
    it any earlier would also move the walk into the link's data.
    """
    original_walk = rar_parser._parse_rar3

    def patched_walk(*args: Any, **kwargs: Any) -> RarArchive:
        archive = original_walk(*args, **kwargs)
        for member in archive.members:
            if member.is_symlink:
                for name in fields:
                    setattr(member, name, value)
        return archive

    monkeypatch.setattr(rar_parser, "_parse_rar3", patched_walk)

    fixture = Path(__file__).parent / "fixtures" / "rar" / "symlinks_solid__rar4.rar"
    with open_archive(fixture) as opened:
        links = [m for m in opened.members() if m.type is MemberType.SYMLINK]
        assert links, "the fixture should still list its symlinks"
        assert all(m.link_target is None for m in links)
        assert _unavailable_reasons(opened) == [reason] * len(links)

    # And what extraction does with it, which is the half the reason name only hints
    # at. Three of these four are targets the archive carries and this read could not
    # reach; recording those as an outcome would drop a symlink the archive describes
    # in full while the report says nothing went wrong. Only `no_target_data` is the
    # archive's own omission.
    #
    # Only the symlinks are extracted, and deliberately: this whole branch reads the
    # target straight out of the archive, so it needs no `unrar` at all, while the
    # fixture's ordinary members do. Extracting everything would make the test require
    # a RARLAB binary for a code path that does not use one, and skip in the
    # `[core-only]` configuration where it runs perfectly well.
    def only_links(m: ArchiveMember) -> bool:
        return m.type is MemberType.SYMLINK

    with tempfile.TemporaryDirectory() as raw_dest:
        dest = Path(raw_dest)
        with open_archive(fixture) as opened:
            report = opened.extract_all(
                dest / "continue", members=only_links, on_error=OnError.CONTINUE
            )
        link_results = report.results
        assert link_results, "the symlinks should reach a write decision"
        if in_archive:
            assert all(r.status is ExtractionStatus.FAILED for r in link_results)
            assert all(
                isinstance(r.error, LinkTargetNotFoundError) for r in link_results
            )
            # The library default aborts on it, as it did before this status existed.
            with (
                open_archive(fixture) as opened,
                pytest.raises(LinkTargetNotFoundError),
            ):
                opened.extract_all(dest / "stop", members=only_links)
        else:
            assert all(
                r.status is ExtractionStatus.LINK_TARGET_UNAVAILABLE
                for r in link_results
            )
            assert all(r.error is None for r in link_results)
            # Not a failure, so the library default carries on through it.
            with open_archive(fixture) as opened:
                opened.extract_all(dest / "stop", members=only_links)


def test_a_rar_symlink_target_split_across_real_volumes_is_joined(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A merged split target is read part by part, not from its first volume onward.

    ``tinyvol_rnn.rar`` + ``.r00`` is a RAR 2.0 set whose one stored, non-solid member
    is split: 1600 bytes starting at byte 68 of a 1000-byte first volume. Merged, it
    has neither split flag. Read in place from its first volume, the target would be
    the rest of volume 1 and the start of volume 2; its recorded parts give the
    member's own bytes. The member is made a symlink through the same constructor hook
    as above: no RAR writer this repo installs makes a RAR4 set.
    """
    original_init = RarMemberInfo.__init__

    def patched_init(self: RarMemberInfo, *args: object, **kwargs: object) -> None:
        original_init(self, *args, **kwargs)  # type: ignore[arg-type]
        self.is_symlink = True

    monkeypatch.setattr(RarMemberInfo, "__init__", patched_init)
    fixtures = Path(__file__).parent / "fixtures" / "rar"
    for source, name in (
        ("tinyvol_rnn.rar", "x.part1.rar"),
        ("tinyvol_rnn.r00", "x.part2.rar"),
    ):
        (tmp_path / name).write_bytes((fixtures / source).read_bytes())

    with open_archive(tmp_path / "x.part1.rar") as opened:
        (link,) = opened.members()
        assert link.type is MemberType.SYMLINK
        raw = link._raw
        assert isinstance(raw, RarMemberInfo)
        assert raw.spanned_volumes
        assert len(raw.data_parts) == 2
        assert not (raw.split_before or raw.split_after)
        assert link.link_target == "ABCDEFGH" * 200
        assert _unavailable_reasons(opened) == []


def test_a_streaming_symlink_is_written(tmp_path: Path) -> None:
    """A ZIP or 7z symlink stores its target as the member's data.

    A streaming pass reaches the write decision with `link_target` still unset: its own
    read of that data comes at EOF. The archive records the target perfectly well, so
    extraction reads it once the selector and filter have accepted the link, and writes
    it. Before that read existed the link failed here; calling it the archive's omission
    instead would have reported success while dropping an ordinary POSIX symlink.
    """
    archive = tmp_path / "unixlink.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("target.txt", b"payload\n")
        info = zipfile.ZipInfo("link")
        info.create_system = 3  # Unix
        info.external_attr = (0o120777 << 16) | 0o120000
        zf.writestr(info, b"target.txt")

    dest = tmp_path / "out"
    with open_archive(archive, streaming=True) as opened:
        report = opened.extract_all(dest)
    by_name = {r.member.name: r for r in report.results}
    assert by_name["link"].status is ExtractionStatus.EXTRACTED
    assert os.readlink(dest / "link") == "target.txt"
    assert by_name["target.txt"].status is ExtractionStatus.EXTRACTED


def _unavailable_reasons(opened: object) -> list[str]:
    """The `reason` of every `SYMLINK_TARGET_UNAVAILABLE` the reader has emitted."""
    return [
        d.context.reason
        for d in opened.diagnostics.retained  # type: ignore[attr-defined]
        if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
    ]
