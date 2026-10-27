"""A damaged link target costs that link its target, not the whole listing.

ZIP, 7z and RAR3/4 store a symlink's target as the member's data, so listing has to
read and verify it. (RAR5 keeps the target in a header record, covered by the header's
own CRC, so it has no data read here to fail.) When that read fails its integrity
check, only the link is wrong: the listing keeps every member, the link has no
``link_target``, and ``SYMLINK_TARGET_UNAVAILABLE`` (``reason="target_data_damaged"``)
says why. The fault itself is raised where the
caller touches the link: opening it, or extracting it.

A target this reader cannot decode at all (an unknown method, a refused variant, an
optional library the data needs that is not installed) is handled the same way, with
``reason="target_data_unsupported"`` or ``"package_not_installed"``.
"""

from __future__ import annotations

import io
import stat
import struct
import zipfile
import zlib
from pathlib import Path

import pytest

from archivey import ExtractionStatus, open_archive
from archivey.config import ArchiveyConfig
from archivey.diagnostics import DiagnosticCode, DiagnosticPolicy, SymlinkTargetContext
from archivey.exceptions import (
    DiagnosticRaisedError,
    PackageNotInstalledError,
    UnsupportedFeatureError,
)
from archivey.internal.streams import codecs as codecs_module, crypto as crypto_module
from archivey.reader import ArchiveReader
from archivey.types import MemberType, OnError
from tests.conftest import requires, requires_binary
from tests.corruption_util import (
    is_corruption_not_truncation,
    raises_corruption_not_truncation,
)
from tests.test_link_target_cap import _sevenzip_with_link
from tests.test_rar_reader import _rar3_file_block, _rar3_main_and_end
from tests.zip_aes_fixture import build_aes_zip

_TARGET = b"zz-link-target-zz"
_PASSWORD = b"secret"


def _flip_byte(blob: bytes, needle: bytes) -> bytes:
    """``blob`` with the first byte of the only ``needle`` inverted."""
    assert blob.count(needle) == 1, f"expected one copy of {needle!r}"
    at = blob.index(needle)
    return blob[:at] + bytes([blob[at] ^ 0xFF]) + blob[at + 1 :]


def _damaged_zip_symlink() -> bytes:
    """A ZIP holding ``target.txt`` and a stored symlink whose data fails its CRC."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("target.txt", b"payload")
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, _TARGET, compress_type=zipfile.ZIP_STORED)
    return _flip_byte(buf.getvalue(), _TARGET)


def _damaged_aes_symlink() -> bytes:
    """A WinZip AES ZIP whose one member is a symlink with a failing HMAC."""
    return build_aes_zip(
        [(b"link", _TARGET)],
        password=_PASSWORD,
        method=0,
        tamper_hmac=True,
        unix_mode=0o120777,
    )


def _damaged_7z_symlink(tmp_path: Path) -> bytes:
    """A stored 7z holding ``target.txt`` and ``link``, a symlink failing its CRC.

    Built as a regular file re-flagged as a link (`_sevenzip_with_link`) rather than
    with ``7z -snl``, which stores a Windows reparse buffer on Windows and exits 1 on
    macOS. 7z stores names as UTF-16, so the ASCII target occurs once, in the data.
    """
    blob = _sevenzip_with_link(tmp_path, _TARGET, store=True, sibling=b"payload")
    return _flip_byte(blob, _TARGET)


_RAR4_LINKS = Path(__file__).parent / "fixtures" / "rar" / "symlinks_solid__rar4.rar"


def _damaged_rar4_symlink() -> bytes:
    """The RAR4 symlink fixture with one byte of a stored target inverted.

    RAR3/4 stores the target uncompressed as the member's data, covered by the data
    CRC32 in the file header; the header CRC does not cover it, so the header still
    parses and only the data check can catch the damage. ``../file1.txt`` is the
    target of ``subdir/link_to_file1.txt`` and occurs nowhere else in the file.
    """
    return _flip_byte(_RAR4_LINKS.read_bytes(), b"../file1.txt")


def _link_diagnostics(ar: ArchiveReader) -> list[SymlinkTargetContext]:
    contexts = []
    for diagnostic in ar.diagnostics.retained:
        if diagnostic.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE:
            assert isinstance(diagnostic.context, SymlinkTargetContext)
            contexts.append(diagnostic.context)
    return contexts


def _assert_listed_targetless(ar: ArchiveReader, name: str = "link") -> None:
    (link,) = [m for m in ar.members() if m.name == name]
    assert link.type is MemberType.SYMLINK
    assert link.link_target is None
    (context,) = _link_diagnostics(ar)
    assert context.reason == "target_data_damaged"
    assert context.member_name == name


def test_damaged_zip_link_target_keeps_the_listing() -> None:
    with open_archive(io.BytesIO(_damaged_zip_symlink())) as ar:
        _assert_listed_targetless(ar)
        assert ar.read(ar.get("target.txt")) == b"payload"
        with raises_corruption_not_truncation():
            ar.open(ar.get("link"))


@pytest.mark.parametrize(
    "passwords", [_PASSWORD, [b"wrong", _PASSWORD]], ids=["single", "candidates"]
)
@requires("cryptography")
def test_damaged_aes_link_target_keeps_the_listing(
    passwords: bytes | list[bytes],
) -> None:
    """Both password paths list the link: its HMAC failure is damage (S28-K4)."""
    with open_archive(io.BytesIO(_damaged_aes_symlink()), password=passwords) as ar:
        _assert_listed_targetless(ar)
        with raises_corruption_not_truncation():
            ar.open(ar.get("link"))


@requires_binary("7z")
def test_damaged_7z_link_target_keeps_the_listing(tmp_path: Path) -> None:
    with open_archive(io.BytesIO(_damaged_7z_symlink(tmp_path))) as ar:
        _assert_listed_targetless(ar)
        assert ar.read(ar.get("target.txt")) == b"payload"
        with raises_corruption_not_truncation():
            ar.open(ar.get("link"))


def test_damaged_link_target_in_a_streaming_pass() -> None:
    with open_archive(io.BytesIO(_damaged_zip_symlink()), streaming=True) as ar:
        names = [member.name for member, _ in ar.stream_members()]
        assert names == ["target.txt", "link"]
        assert [c.reason for c in _link_diagnostics(ar)] == ["target_data_damaged"]


def _damaged_link_case(fmt: str, tmp_path: Path) -> tuple[bytes, str]:
    """An archive with one damaged data-stored symlink target, and the link's name."""
    if fmt == "zip":
        return _damaged_zip_symlink(), "link"
    if fmt == "7z":
        return _damaged_7z_symlink(tmp_path), "link"
    if fmt == "rar4-solid":
        return _damaged_rar4_symlink(), _RAR4_DAMAGED
    raise AssertionError(fmt)


# Each format's own pass: ZIP the base pass, 7z its folder pass, the solid RAR4 fixture
# the solid RAR pass. That pass spawns ``unrar`` only on the first data read, and these
# tests read none, so they need no RAR binary; ``7z`` builds the 7z fixture.
_PASS_FORMATS = [
    pytest.param("zip", id="zip"),
    pytest.param("7z", id="7z", marks=requires_binary("7z")),
    pytest.param("rar4-solid", id="rar4-solid"),
]


@pytest.mark.parametrize("fmt", _PASS_FORMATS)
@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "streaming"])
def test_damaged_link_target_in_a_pass_left_early(
    tmp_path: Path, fmt: str, streaming: bool
) -> None:
    """A pass the caller leaves at the link never resolves links, yet reports it.

    The pass reads the target when it reaches the link, so the damage is known there;
    reported only by the link finalization a finished pass runs, it went unreported.
    """
    blob, link = _damaged_link_case(fmt, tmp_path)
    with open_archive(io.BytesIO(blob), streaming=streaming) as ar:
        for member, _ in ar.stream_members():
            if member.name == link:
                break
        assert [c.reason for c in _link_diagnostics(ar)] == ["target_data_damaged"]


@pytest.mark.parametrize("fmt", _PASS_FORMATS)
@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "streaming"])
def test_damaged_link_target_under_strict_policy_refuses_the_pass(
    tmp_path: Path, fmt: str, streaming: bool
) -> None:
    """A strict pass refuses before handing out the link it cannot vouch for."""
    blob, link = _damaged_link_case(fmt, tmp_path)
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    seen = []
    with (
        open_archive(io.BytesIO(blob), streaming=streaming, config=config) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        for member, _ in ar.stream_members():
            seen.append(member.name)
    assert link not in seen


@pytest.mark.parametrize("fmt", _PASS_FORMATS)
def test_damaged_link_target_in_a_finished_pass_is_reported_once(
    tmp_path: Path, fmt: str
) -> None:
    """Link finalization does not report again a link the pass already reported."""
    blob, _ = _damaged_link_case(fmt, tmp_path)
    with open_archive(io.BytesIO(blob), streaming=True) as ar:
        for _ in ar.stream_members():
            pass
        assert [c.reason for c in _link_diagnostics(ar)] == ["target_data_damaged"]


def test_damaged_link_target_in_a_streaming_extraction_is_reported_once(
    tmp_path: Path,
) -> None:
    with open_archive(io.BytesIO(_damaged_zip_symlink()), streaming=True) as ar:
        report = ar.extract_all(tmp_path / "out", on_error=OnError.CONTINUE)
        assert [c.reason for c in _link_diagnostics(ar)] == ["target_data_damaged"]
    by_name = {result.member.name: result for result in report.results}
    assert by_name["link"].status is ExtractionStatus.FAILED
    assert is_corruption_not_truncation(by_name["link"].error)


def test_damaged_link_target_fails_only_that_link_at_extraction(
    tmp_path: Path,
) -> None:
    with open_archive(io.BytesIO(_damaged_zip_symlink())) as ar:
        report = ar.extract_all(tmp_path / "out", on_error=OnError.CONTINUE)
    by_name = {result.member.name: result for result in report.results}
    assert by_name["target.txt"].status is ExtractionStatus.EXTRACTED
    assert by_name["link"].status is ExtractionStatus.FAILED
    assert is_corruption_not_truncation(by_name["link"].error)
    assert (tmp_path / "out" / "target.txt").read_bytes() == b"payload"
    assert not (tmp_path / "out" / "link").is_symlink()


def test_damaged_link_target_under_strict_policy_refuses_the_listing() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        open_archive(io.BytesIO(_damaged_zip_symlink()), config=config) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        ar.members()


_RAR4_DAMAGED = "subdir/link_to_file1.txt"


def test_damaged_rar4_link_target_keeps_the_listing() -> None:
    with open_archive(io.BytesIO(_damaged_rar4_symlink())) as ar:
        _assert_listed_targetless(ar, _RAR4_DAMAGED)
        # The other links' targets are intact and still resolve.
        assert ar.get("symlink_to_file1.txt").link_target == "file1.txt"
        with raises_corruption_not_truncation():
            ar.open(ar.get(_RAR4_DAMAGED))


@requires_binary("unrar")  # file1.txt is RAR member data, which needs a data program
def test_damaged_rar4_link_target_fails_only_that_link_at_extraction(
    tmp_path: Path,
) -> None:
    with open_archive(io.BytesIO(_damaged_rar4_symlink())) as ar:
        report = ar.extract_all(tmp_path / "out", on_error=OnError.CONTINUE)
    by_name = {result.member.name: result for result in report.results}
    assert by_name["file1.txt"].status is ExtractionStatus.EXTRACTED
    assert by_name[_RAR4_DAMAGED].status is ExtractionStatus.FAILED
    assert is_corruption_not_truncation(by_name[_RAR4_DAMAGED].error)
    assert not (tmp_path / "out" / "subdir" / "link_to_file1.txt").is_symlink()


def test_damaged_rar4_link_target_under_strict_policy_refuses_the_listing() -> None:
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        open_archive(io.BytesIO(_damaged_rar4_symlink()), config=config) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        ar.members()


def _rar4_symlink_with_sizes(packed: bytes, declared: int) -> bytes:
    """A RAR3 stored symlink packing ``packed`` whose header declares ``declared``.

    The data CRC32 is forged over the bytes an in-place read of the declared size
    returns: the packed bytes, the end-of-archive block, then trailing bytes that
    belong to no member. So only the size check can refuse it.
    """
    main_hdr, end_hdr = _rar3_main_and_end()
    trailing = b"/etc/shadow-and-more-attacker-bytes" * 200
    read = (packed + end_hdr + trailing)[:declared]
    block = _rar3_file_block(
        b"link",
        flags=0,
        pack_lo=len(packed),
        unp_lo=declared,
        attributes=0o120777,
        crc32=zlib.crc32(read),
    )
    return b"Rar!\x1a\x07\x00" + main_hdr + block + packed + end_hdr + trailing


@pytest.mark.parametrize(
    ("packed", "declared"),
    [
        pytest.param(b"a.txt", 40, id="declares-more"),
        # Over the link-target cap: still damage, not an oversized target.
        pytest.param(b"a.txt", 5000, id="declares-more-than-the-cap"),
        # Declares nothing but packs a target: damage, not a link with no target.
        pytest.param(b"/etc/motd", 0, id="declares-zero"),
    ],
)
def test_rar4_link_target_whose_sizes_disagree_is_refused(
    tmp_path: Path, packed: bytes, declared: int
) -> None:
    """A stored target is its packed bytes; a declared size that differs is damage.

    Reading a larger declared size would take the end-of-archive block and the bytes
    after it as the target, and with the CRC forged over them nothing else would
    notice. Either way the link fails at extraction rather than being written or
    reported as an archive that recorded no target.
    """
    blob = _rar4_symlink_with_sizes(packed, declared)
    with open_archive(io.BytesIO(blob)) as ar:
        _assert_listed_targetless(ar)
        with raises_corruption_not_truncation():
            ar.open(ar.get("link"))
    with open_archive(io.BytesIO(blob)) as ar:
        report = ar.extract_all(tmp_path / "out", on_error=OnError.CONTINUE)
    (result,) = report.results
    assert result.status is ExtractionStatus.FAILED
    assert is_corruption_not_truncation(result.error)


# A link target the reader cannot decode (DR-2): an unknown method, a variant it
# refuses, or an optional library it needs that is not installed. Like damage, this is about the
# link's own data, so it costs that link its target and nothing else. The reason
# differs, and opening or extracting the link raises the error the read raised.


def _undecodable_zip_symlink(*, method: int = 0, flags: int = 0) -> bytes:
    """``target.txt``, ``link`` and ``after.txt``, with only ``link``'s method or
    general-purpose flags patched, in both its headers."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("target.txt", b"payload")
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, b"target.txt", compress_type=zipfile.ZIP_STORED)
        zf.writestr("after.txt", b"after")
    blob = bytearray(buf.getvalue())
    # (signature, offset of flags then method, offset of the name length, fixed size)
    for signature, fields, name_len_at, fixed in (
        (b"PK\x03\x04", 6, 26, 30),
        (b"PK\x01\x02", 8, 28, 46),
    ):
        at = blob.find(signature)
        while at >= 0:
            name_len = struct.unpack_from("<H", blob, at + name_len_at)[0]
            if blob[at + fixed : at + fixed + name_len] == b"link":
                struct.pack_into("<HH", blob, at + fields, flags, method)
            at = blob.find(signature, at + 4)
    return bytes(blob)


_UNDECODABLE_ZIP = [
    pytest.param({"method": 7}, "compression method 7", id="unknown-method"),
    pytest.param({"flags": 0x20}, "bit 5", id="patched-data"),
]


def _reasons(ar: ArchiveReader) -> list[str]:
    return [context.reason for context in _link_diagnostics(ar)]


@pytest.mark.parametrize(("patch", "match"), _UNDECODABLE_ZIP)
def test_undecodable_zip_link_target_keeps_the_listing(
    patch: dict[str, int], match: str
) -> None:
    with open_archive(io.BytesIO(_undecodable_zip_symlink(**patch))) as ar:
        assert [m.name for m in ar.members()] == ["target.txt", "link", "after.txt"]
        link = ar.get("link")
        assert link.type is MemberType.SYMLINK
        assert link.link_target is None
        assert _reasons(ar) == ["target_data_unsupported"]
        assert ar.read(ar.get("after.txt")) == b"after"
        with pytest.raises(UnsupportedFeatureError, match=match):
            ar.open(link)


@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "streaming"])
@pytest.mark.parametrize(("patch", "match"), _UNDECODABLE_ZIP)
def test_undecodable_zip_link_target_in_a_pass(
    patch: dict[str, int], match: str, streaming: bool
) -> None:
    blob = _undecodable_zip_symlink(**patch)
    with open_archive(io.BytesIO(blob), streaming=streaming) as ar:
        names = [member.name for member, _ in ar.stream_members()]
        assert names == ["target.txt", "link", "after.txt"]
        assert _reasons(ar) == ["target_data_unsupported"]


# (method, whether the zstd backend is hidden, the error, the reason)
_UNDECODABLE_CASES = [
    pytest.param(
        7, False, UnsupportedFeatureError, "target_data_unsupported", id="unsupported"
    ),
    pytest.param(
        93, True, PackageNotInstalledError, "package_not_installed", id="not-installed"
    ),
]


@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "streaming"])
@pytest.mark.parametrize(("method", "hide_zstd", "error", "reason"), _UNDECODABLE_CASES)
def test_undecodable_zip_link_target_fails_only_that_link_at_extraction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    streaming: bool,
    method: int,
    hide_zstd: bool,
    error: type[Exception],
    reason: str,
) -> None:
    if hide_zstd:
        monkeypatch.setattr(codecs_module.deps, "zstd", None)
    blob = _undecodable_zip_symlink(method=method)
    with open_archive(io.BytesIO(blob), streaming=streaming) as ar:
        report = ar.extract_all(tmp_path / "out", on_error=OnError.CONTINUE)
        assert _reasons(ar) == [reason]
    by_name = {result.member.name: result for result in report.results}
    assert by_name["target.txt"].status is ExtractionStatus.EXTRACTED
    assert by_name["after.txt"].status is ExtractionStatus.EXTRACTED
    assert by_name["link"].status is ExtractionStatus.FAILED
    assert isinstance(by_name["link"].error, error)
    assert not (tmp_path / "out" / "link").is_symlink()


@pytest.mark.parametrize(("method", "hide_zstd", "error", "reason"), _UNDECODABLE_CASES)
def test_undecodable_link_target_under_strict_policy_refuses_the_listing(
    monkeypatch: pytest.MonkeyPatch,
    method: int,
    hide_zstd: bool,
    error: type[Exception],
    reason: str,
) -> None:
    """Strict refuses even when the archive is intact and only a library is missing,
    as it does for a link whose password is missing."""
    if hide_zstd:
        monkeypatch.setattr(codecs_module.deps, "zstd", None)
    config = ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    blob = _undecodable_zip_symlink(method=method)
    with (
        open_archive(io.BytesIO(blob), config=config) as ar,
        pytest.raises(DiagnosticRaisedError),
    ):
        ar.members()


@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "streaming"])
def test_zip_link_target_without_its_codec_keeps_the_listing(
    monkeypatch: pytest.MonkeyPatch, streaming: bool
) -> None:
    """A missing optional codec (DR-5) costs only the link that needs it."""
    monkeypatch.setattr(codecs_module.deps, "zstd", None)
    blob = _undecodable_zip_symlink(method=93)
    with open_archive(io.BytesIO(blob), streaming=streaming) as ar:
        names = [member.name for member, _ in ar.stream_members()]
        assert names == ["target.txt", "link", "after.txt"]
        assert _reasons(ar) == ["package_not_installed"]
    with open_archive(io.BytesIO(blob)) as ar:
        assert ar.get("link").link_target is None
        assert _reasons(ar) == ["package_not_installed"]
        with pytest.raises(PackageNotInstalledError):
            ar.open(ar.get("link"))


@requires("cryptography")  # to write the fixture; the read then runs without it
def test_aes_link_target_without_cryptography_keeps_the_listing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``cryptography`` is the optional library a WinZip AES member's data needs: its
    absence costs the link its target, as a missing codec does."""
    blob = build_aes_zip(
        [(b"link", _TARGET)], password=_PASSWORD, method=0, unix_mode=0o120777
    )
    monkeypatch.setattr(crypto_module, "_crypto_available", lambda: False)
    with open_archive(io.BytesIO(blob), password=_PASSWORD) as ar:
        (link,) = ar.members()
        assert link.type is MemberType.SYMLINK
        assert link.link_target is None
        assert _reasons(ar) == ["package_not_installed"]
        with pytest.raises(PackageNotInstalledError, match="cryptography"):
            ar.open(link)


def _undecodable_7z_symlink(tmp_path: Path, method: str) -> bytes:
    """A 7z holding ``target.txt`` and ``link``, both compressed with ``method``."""
    return _sevenzip_with_link(
        tmp_path, b"target.txt", sibling=b"payload", method=method
    )


@requires_binary("7z")
def test_undecodable_7z_link_target_keeps_the_listing(tmp_path: Path) -> None:
    # lc=8: what `7z a -m0=LZMA:lc=8` writes; liblzma decodes lc + lp up to 4.
    blob = _undecodable_7z_symlink(tmp_path, "LZMA:lc=8")
    with open_archive(io.BytesIO(blob)) as ar:
        assert sorted(m.name for m in ar.members()) == ["link", "target.txt"]
        assert ar.get("link").link_target is None
        assert _reasons(ar) == ["target_data_unsupported"]
        with pytest.raises(UnsupportedFeatureError, match="lc=8"):
            ar.open(ar.get("link"))


@requires_binary("7z")
@pytest.mark.parametrize("streaming", [False, True], ids=["seekable", "streaming"])
def test_undecodable_7z_link_target_in_a_pass(tmp_path: Path, streaming: bool) -> None:
    blob = _undecodable_7z_symlink(tmp_path, "LZMA:lc=8")
    with open_archive(io.BytesIO(blob), streaming=streaming) as ar:
        names = sorted(member.name for member, _ in ar.stream_members())
        assert names == ["link", "target.txt"]
        assert _reasons(ar) == ["target_data_unsupported"]


@requires_binary("7z")
def test_7z_link_target_without_its_codec_keeps_the_listing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    blob = _undecodable_7z_symlink(tmp_path, "PPMd")
    monkeypatch.setattr(
        codecs_module.deps,
        "pyppmd",
        codecs_module.deps.LazyOptional("pyppmd", present=False),
    )
    with open_archive(io.BytesIO(blob)) as ar:
        assert sorted(m.name for m in ar.members()) == ["link", "target.txt"]
        assert ar.get("link").link_target is None
        assert _reasons(ar) == ["package_not_installed"]
        with pytest.raises(PackageNotInstalledError, match="pyppmd"):
            ar.open(ar.get("link"))
