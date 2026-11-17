"""Windows link targets in ZIP, 7z and RAR5: one listing, one extraction outcome.

A Windows symlink or junction stores a Windows path. ZIP and 7z keep it in a reparse
data buffer (the member's data), RAR5 in a redirect record of type 2 or 3. All three go
through ``windows_reparse.normalize_windows_link_target``, so ``\\??\\C:\\Windows``
lists as ``C:/Windows`` and ``..\\up\\x`` as ``../up/x`` in every format, as unrar
(``DosSlashToUnix``) and 7-Zip present them.

Extraction then applies the maintainer's ruling of 2026-10-06 (portability: one archive
gives one outcome on every OS, and Windows already refuses drive paths): a symlink
target with a drive letter or a UNC root is refused at every policy on every OS,
except one rooted by a single ``\\``, which POSIX reads as a filename. A ``:`` or a
Windows-reserved device name in a target segment is refused under ``STRICT`` and
``STANDARD``, as it is in a member name; ``TRUSTED`` keeps deferring to the OS.

A hardlink target is not a path. It names an earlier member (maintainer decision,
2026-10-07), and the link gets what its source gets: the member at the end of its
chain (``link_target_member``), which here is always the member the target names. The
link is refused where the source is refused and linked where it is written.
``tests/test_hardlink_target_rule.py`` has the full matrix, chains included.
"""

from __future__ import annotations

import io
import os
import struct
import tarfile
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

from archivey import (
    ArchiveyConfig,
    ExtractionPolicy,
    ExtractionStatus,
    OnError,
    open_archive,
    sanitize_names,
)
from archivey.exceptions import FilterRejectionError
from archivey.internal.windows_reparse import (
    FILE_ATTRIBUTE_REPARSE_POINT,
    IO_REPARSE_TAG_MOUNT_POINT,
    IO_REPARSE_TAG_SYMLINK,
    normalize_windows_link_target,
)
from archivey.types import ArchiveMember, MemberType
from tests.test_audit_rar_iso_dir import (
    _fixture,
    _rar5_build,
    _rar5_parse,
    _read_vint,
    _vint,
)

_FILE_ATTRIBUTE_ARCHIVE = 0x20

_DRIVE_OR_UNC = "Symlink target is a Windows drive or UNC path"
_ESCAPES = "Symlink target escapes destination"
_COLON = "Colon in link target segment"
_RESERVED = "Windows-reserved device name in link target"

# (stored target, listed target, outcome under STRICT/STANDARD, outcome under TRUSTED).
# An outcome is the start of the refusal message, or None for an extracted link.
_CASES: list[tuple[str, str, str | None, str | None]] = [
    ("\\??\\C:\\Windows", "C:/Windows", _DRIVE_OR_UNC, _DRIVE_OR_UNC),
    ("/??/C:/Windows", "C:/Windows", _DRIVE_OR_UNC, _DRIVE_OR_UNC),
    ("\\??\\UNC\\srv\\share", "//srv/share", _DRIVE_OR_UNC, _DRIVE_OR_UNC),
    ("..\\up\\x", "../up/x", _ESCAPES, _ESCAPES),
    ("C:\\abs\\y", "C:/abs/y", _DRIVE_OR_UNC, _DRIVE_OR_UNC),
    ("rel\\sub", "rel/sub", None, None),
    # A one-letter name before the colon is a drive to Windows (drive-relative T:).
    ("t:stream", "t:stream", _DRIVE_OR_UNC, _DRIVE_OR_UNC),
    # Longer than one letter, it is a file and an NTFS alternate data stream.
    ("file:stream", "file:stream", _COLON, None),
    ("sub\\NUL", "sub/NUL", _RESERVED, None),
]
_IDS = [
    "nt-drive",
    "rar51-drive",
    "nt-unc",
    "dotdot",
    "bare-drive",
    "relative",
    "one-letter-colon",
    "ads",
    "reserved",
]


# --- builders -----------------------------------------------------------------


def _reparse_buffer(substitute: str, *, junction: bool) -> bytes:
    """A REPARSE_DATA_BUFFER with ``substitute`` and an empty PrintName."""
    subst = substitute.encode("utf-16-le") + b"\0\0"
    printed = b"\0\0"
    names = struct.pack("<HHHH", 0, len(subst) - 2, len(subst), 0)
    flags = b"" if junction else struct.pack("<I", 0)
    body = names + flags + subst + printed
    tag = IO_REPARSE_TAG_MOUNT_POINT if junction else IO_REPARSE_TAG_SYMLINK
    return struct.pack("<IHH", tag, len(body), 0) + body


def _link_names(count: int) -> list[str]:
    return [f"link{index}" for index in range(count)]


def _build_zip(path: Path, targets: list[str], *, junction: bool) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, target in zip(_link_names(len(targets)), targets):
            info = zipfile.ZipInfo(name)
            info.create_system = 0  # FAT, as every Windows writer of these uses
            info.external_attr = _FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_REPARSE_POINT
            zf.writestr(info, _reparse_buffer(target, junction=junction))


def _7z_number(value: int) -> bytes:
    for extra in range(8):
        if value < 1 << (7 * (extra + 1)):
            first = ((0xFF << (8 - extra)) & 0xFF) | (value >> (8 * extra))
            return bytes([first]) + value.to_bytes(8, "little")[:extra]
    return b"\xff" + value.to_bytes(8, "little")


def _build_7z(path: Path, targets: list[str], *, junction: bool) -> None:
    """A 7z archive with one Copy folder holding each link's reparse buffer."""
    datas = [_reparse_buffer(target, junction=junction) for target in targets]
    names = _link_names(len(targets))
    packed = b"".join(datas)
    num = _7z_number
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
    name_data = b"\x00" + b"".join(n.encode("utf-16-le") + b"\0\0" for n in names)
    attr = _FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_REPARSE_POINT
    attr_data = b"\x01\x00" + struct.pack("<I", attr) * len(names)
    files = (
        b"\x05"
        + num(len(names))
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


def _build_rar5(path: Path, targets: list[str], *, junction: bool) -> None:
    """RAR5 redirect members of type 2 (Windows symlink) or 3 (junction).

    ``rar`` writes only Unix symlinks on Linux, so the redirect record of a committed
    symlink is rewritten, the way ``tests/test_audit_rar_iso_dir.py`` rewrites names.
    """
    blocks = _rar5_parse(_fixture("symlinks_solid__.rar").read_bytes())
    main = next(block for block in blocks if block["type"] == 1)
    main["body"] = bytes([main["body"][0] & ~0x04]) + main["body"][1:]
    template = next(b for b in blocks if b.get("name") == b"symlink_to_file1.txt")
    end = next(block for block in blocks if block["type"] == 5)
    # The extra area is the time record, then the redirect record.
    time_record_size, _ = _read_vint(template["extra"], 0)
    time_record = template["extra"][: 1 + time_record_size]
    redirect_type = 3 if junction else 2
    links = []
    for name, target in zip(_link_names(len(targets)), targets):
        encoded = target.encode()
        body = _vint(5) + _vint(redirect_type) + _vint(0) + _vint(len(encoded))
        body += encoded
        link = dict(template)
        link["name"] = name.encode()
        link["cinfo"] = template["cinfo"] & ~0x40
        link["extra"] = time_record + _vint(len(body)) + body
        links.append(link)
    path.write_bytes(_rar5_build([main, *links, end]))


_Builder = Callable[..., None]
_FORMATS: list[tuple[str, _Builder]] = [
    ("zip", _build_zip),
    ("7z", _build_7z),
    ("rar", _build_rar5),
]


@pytest.fixture(params=_FORMATS, ids=[f for f, _ in _FORMATS])
def built(request: pytest.FixtureRequest, tmp_path: Path) -> Callable[..., Path]:
    suffix, builder = request.param

    def build(targets: list[str], *, junction: bool = False) -> Path:
        path = tmp_path / f"links.{suffix}"
        builder(path, targets, junction=junction)
        return path

    return build


# --- the normalizer -----------------------------------------------------------


@pytest.mark.parametrize(("stored", "listed"), [(c[0], c[1]) for c in _CASES], ids=_IDS)
def test_normalizer(stored: str, listed: str) -> None:
    assert normalize_windows_link_target(stored) == listed


@pytest.mark.parametrize(
    "stored",
    ["\\\\?\\UNC\\srv\\share", "/??/unc/srv/share", "//?/UNC/srv/share"],
)
def test_every_unc_spelling_keeps_its_root(stored: str) -> None:
    assert normalize_windows_link_target(stored) == "//srv/share"


# --- listing ------------------------------------------------------------------


@pytest.mark.parametrize("junction", [False, True], ids=["symlink", "junction"])
def test_windows_link_targets_list_alike_in_every_format(
    built: Callable[..., Path], junction: bool
) -> None:
    path = built([c[0] for c in _CASES], junction=junction)
    with open_archive(path) as archive:
        members = archive.members()
    assert [m.type for m in members] == [MemberType.SYMLINK] * len(_CASES)
    assert [m.link_target for m in members] == [c[1] for c in _CASES]
    assert all(m.is_reparse_point for m in members)


def test_a_rar5_unix_symlink_keeps_its_backslash(tmp_path: Path) -> None:
    """Type 1 is a POSIX symlink: ``\\`` is an ordinary character there."""
    blocks = _rar5_parse(_fixture("symlinks_solid__.rar").read_bytes())
    for block in blocks:
        if block.get("name") == b"symlink_to_file1.txt":
            block["extra"] = block["extra"].replace(
                b"\r\x05\x01\x00\tfile1.txt", b"\r\x05\x01\x00\tfile1\\txt"
            )
    path = tmp_path / "unix.rar"
    path.write_bytes(_rar5_build(blocks))
    with open_archive(path) as archive:
        member = archive.get("symlink_to_file1.txt")
    assert member is not None
    assert member.link_target == "file1\\txt"
    assert not member.is_reparse_point


# --- extraction ---------------------------------------------------------------


@pytest.mark.parametrize("policy", list(ExtractionPolicy), ids=lambda p: p.name)
def test_windows_link_targets_extract_alike_in_every_format(
    built: Callable[..., Path], tmp_path: Path, policy: ExtractionPolicy
) -> None:
    path = built([c[0] for c in _CASES])
    dest = tmp_path / "out"
    with open_archive(path) as archive:
        report = archive.extract_all(
            dest, policy=policy, on_error=OnError.CONTINUE, on_blocked="skip"
        )
    for case_id, case, result in zip(_IDS, _CASES, report.results, strict=True):
        _stored, listed, guarded, trusted = case
        expected = trusted if policy is ExtractionPolicy.TRUSTED else guarded
        link = dest / result.member.name
        if expected is None:
            if os.name == "nt":
                continue  # creating a symlink needs a privilege CI may not hold
            assert result.status is ExtractionStatus.EXTRACTED, case_id
            assert os.readlink(link) == listed, case_id
        else:
            assert result.status is ExtractionStatus.BLOCKED, case_id
            assert isinstance(result.error, FilterRejectionError), case_id
            assert result.error.message.startswith(expected), (case_id, result.error)
            assert result.error.link_target == listed, case_id
            assert not os.path.lexists(link), case_id


@pytest.mark.parametrize("policy", list(ExtractionPolicy), ids=lambda p: p.name)
@pytest.mark.parametrize(
    "target", ["C:/x", "c:x", "//host/share", "\\\\host\\share", "/\\host"]
)
def test_a_tar_symlink_with_a_windows_root_is_refused(
    tmp_path: Path, policy: ExtractionPolicy, target: str
) -> None:
    """The rule is about the target string, so it holds for a POSIX format too."""
    path = tmp_path / "a.tar"
    with tarfile.open(path, "w") as tf:
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = target
        tf.addfile(info)
    with open_archive(path) as archive:
        (result,) = archive.extract_all(
            tmp_path / "out",
            policy=policy,
            on_error=OnError.CONTINUE,
            on_blocked="skip",
        ).results
    assert result.status is ExtractionStatus.BLOCKED
    assert isinstance(result.error, FilterRejectionError)
    assert result.error.message == _DRIVE_OR_UNC


def _tar(path: Path, entries: list[tuple[str, bytes, str | None]]) -> Path:
    """A tar of ``(name, type, linkname)`` entries; a regular file holds ``b"data"``."""
    with tarfile.open(path, "w") as tf:
        for name, kind, linkname in entries:
            info = tarfile.TarInfo(name)
            info.type = kind
            if linkname is not None:
                info.linkname = linkname
            if kind == tarfile.REGTYPE:
                info.size = 4
                tf.addfile(info, io.BytesIO(b"data"))
            else:
                tf.addfile(info)
    return path


@pytest.mark.parametrize("policy", list(ExtractionPolicy), ids=lambda p: p.name)
@pytest.mark.parametrize("target", ["C:/x", "//host/share/x", "c:x"])
def test_a_hardlink_to_a_member_with_a_windows_root_gets_what_the_member_gets(
    tmp_path: Path, policy: ExtractionPolicy, target: str
) -> None:
    """The link follows the member its target names, never the target as a path:
    ``STANDARD`` and ``TRUSTED`` re-root ``C:/x`` and ``//host/share/x`` and link to
    the result, and every policy refuses ``c:x`` (no root to drop), and its link."""
    path = _tar(
        tmp_path / "a.tar",
        [(target, tarfile.REGTYPE, None), ("hl", tarfile.LNKTYPE, target)],
    )
    dest = tmp_path / "out"
    with open_archive(path) as archive:
        report = archive.extract_all(
            dest, policy=policy, on_error=OnError.CONTINUE, on_blocked="skip"
        )
    member, link = report.results
    if policy is ExtractionPolicy.STRICT or target == "c:x":
        assert member.status is ExtractionStatus.BLOCKED
        assert link.status is ExtractionStatus.BLOCKED
        assert isinstance(link.error, FilterRejectionError)
        assert link.error.message == "Hardlink target was refused"
        assert not os.path.lexists(dest / "hl")
    else:
        assert member.status is ExtractionStatus.EXTRACTED, member.error
        assert link.status is ExtractionStatus.EXTRACTED, link.error
        assert (dest / "hl").read_bytes() == b"data"


@pytest.mark.skipif(os.name == "nt", reason="a backslash is a separator on Windows")
@pytest.mark.parametrize("policy", list(ExtractionPolicy), ids=lambda p: p.name)
def test_a_backslash_rooted_symlink_target_extracts_on_posix(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """The rule's named exception: on POSIX ``\\foo`` is a relative name. It holds only
    under ``TRUSTED``; the portable policies write a TAR ``\\`` as ``/``, so the
    target is the rooted ``/foo`` and leaves the destination."""
    path = _tar(tmp_path / "a.tar", [("bs", tarfile.SYMTYPE, "\\foo")])
    dest = tmp_path / "out"
    with open_archive(path) as archive:
        (result,) = archive.extract_all(
            dest, policy=policy, on_error=OnError.CONTINUE, on_blocked="skip"
        ).results
    if policy is ExtractionPolicy.TRUSTED:
        assert result.status is ExtractionStatus.EXTRACTED, result.error
        assert os.readlink(dest / "bs") == "\\foo"
    else:
        assert result.status is ExtractionStatus.BLOCKED
        assert isinstance(result.error, FilterRejectionError)
        assert result.error.message == "Symlink target escapes destination"
        assert not os.path.lexists(dest / "bs")


@pytest.mark.parametrize("policy", list(ExtractionPolicy), ids=lambda p: p.name)
def test_a_backslash_rooted_hardlink_target_gets_what_its_member_gets(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """The ``\\foo`` exception is for symlinks only, and a hardlink needs none: its
    target names the member ``\\x``. ``STRICT`` refuses that member, on every OS
    (Windows would resolve it off the drive root), so it refuses the link; the other
    policies re-root the member and link to it."""
    path = _tar(
        tmp_path / "a.tar",
        [("\\x", tarfile.REGTYPE, None), ("hl", tarfile.LNKTYPE, "\\x")],
    )
    dest = tmp_path / "out"
    with open_archive(path) as archive:
        report = archive.extract_all(
            dest, policy=policy, on_error=OnError.CONTINUE, on_blocked="skip"
        )
    member, link = report.results
    if policy is ExtractionPolicy.STRICT:
        assert member.status is ExtractionStatus.BLOCKED
        assert link.status is ExtractionStatus.BLOCKED
        assert isinstance(link.error, FilterRejectionError)
        assert link.error.message == "Hardlink target was refused"
        assert not os.path.lexists(dest / "hl")
    else:
        assert member.status is ExtractionStatus.EXTRACTED, member.error
        assert link.status is ExtractionStatus.EXTRACTED, link.error
        assert (dest / "x").read_bytes() == b"data"
        assert (dest / "hl").read_bytes() == b"data"


def test_sanitize_names_rewrites_a_symlink_target_s_segments(tmp_path: Path) -> None:
    """The link points at the name the filter gave the member it links to; a drive
    target is not rewritten into a different link and stays refused."""
    path = _tar(
        tmp_path / "a.tar",
        [
            ("file:stream", tarfile.REGTYPE, None),
            ("link", tarfile.SYMTYPE, "file:stream"),
            ("dev", tarfile.SYMTYPE, "sub/NUL"),
            ("up", tarfile.SYMTYPE, "../out/file:stream"),
            ("drv", tarfile.SYMTYPE, "C:/x"),
        ],
    )
    dest = tmp_path / "out"
    with open_archive(path) as archive:
        report = archive.extract_all(
            dest,
            policy=ExtractionPolicy.STANDARD,
            filter=sanitize_names,
            on_error=OnError.CONTINUE,
            on_blocked="skip",
        )
    results = {r.member.name: r for r in report.results}
    assert results["file:stream"].status is ExtractionStatus.EXTRACTED
    assert (dest / "file_stream").read_bytes() == b"data"
    drv = results["drv"]
    assert drv.status is ExtractionStatus.BLOCKED
    assert isinstance(drv.error, FilterRejectionError)
    assert drv.error.message == _DRIVE_OR_UNC
    if os.name == "nt":
        return  # creating a symlink needs a privilege CI may not hold
    for name, written in [
        ("link", "file_stream"),
        ("dev", "sub/NUL_"),
        # ``..`` is kept: a symlink target is relative to the link, not re-rooted.
        ("up", "../out/file_stream"),
    ]:
        assert results[name].status is ExtractionStatus.EXTRACTED, results[name].error
        assert os.readlink(dest / name) == written


@pytest.mark.parametrize("streaming", [False, True], ids=["random-access", "streaming"])
@pytest.mark.parametrize(
    "read_link_targets", [True, False], ids=["read-targets", "late-targets"]
)
def test_sanitize_names_rewrites_a_symlink_target_read_after_the_filter(
    tmp_path: Path, read_link_targets: bool, streaming: bool
) -> None:
    """A ZIP keeps a symlink's target in member data. Under ``read_link_targets=False``,
    or in a streaming pass, extraction reads it only after the filter accepted the
    link, so the filter is called again with the target, and the outcome is the one
    random access with the default config gives."""
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("file:stream", b"data")
        info = zipfile.ZipInfo("link")
        info.create_system = 3  # Unix
        info.external_attr = 0o120777 << 16
        zf.writestr(info, b"file:stream")
    dest = tmp_path / "out"
    seen: list[str | None] = []

    def recording(member: ArchiveMember) -> ArchiveMember:
        if member.name == "link":
            seen.append(member.link_target)
        return sanitize_names(member)

    config = ArchiveyConfig(read_link_targets=read_link_targets)
    with open_archive(path, streaming=streaming, config=config) as archive:
        report = archive.extract_all(
            dest,
            policy=ExtractionPolicy.STANDARD,
            filter=recording,
            on_error=OnError.CONTINUE,
            on_blocked="skip",
        )
    assert seen[-1] == "file:stream"
    results = {r.member.name: r for r in report.results}
    assert (dest / "file_stream").read_bytes() == b"data"
    link = results["link"]
    if os.name == "nt":
        return  # creating a symlink needs a privilege CI may not hold
    assert link.status is ExtractionStatus.EXTRACTED, link.error
    assert os.readlink(dest / "link") == "file_stream"


@pytest.mark.parametrize("policy", list(ExtractionPolicy), ids=lambda p: p.name)
def test_sanitize_names_removes_a_bidi_override_before_a_drive_target(
    tmp_path: Path, policy: ExtractionPolicy
) -> None:
    """The drive target keeps its root and stays refused, but not its bidi override:
    the link is refused for the drive at every policy, ``TRUSTED`` included."""
    path = _tar(tmp_path / "a.tar", [("drv", tarfile.SYMTYPE, "\u202eC:/x")])
    with open_archive(path) as archive:
        (listed,) = archive.members()
        assert sanitize_names(listed).link_target == "C:/x"
        (result,) = archive.extract_all(
            tmp_path / "out",
            policy=policy,
            filter=sanitize_names,
            on_error=OnError.CONTINUE,
            on_blocked="skip",
        ).results
    assert result.status is ExtractionStatus.BLOCKED
    assert isinstance(result.error, FilterRejectionError)
    assert result.error.message == _DRIVE_OR_UNC
