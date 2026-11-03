"""7z member names that hold a lone UTF-16 surrogate (U+D800-U+DFFF).

A 7z name is a sequence of UTF-16 code units, and NTFS allows any 16-bit unit in a
file name, so a 7z made on Windows can carry a surrogate that has no partner. The
names decode with ``surrogatepass`` and keep the surrogate, as 7-Zip does. Under
``STRICT`` and ``STANDARD`` extraction percent-escapes the surrogate's UTF-8 bytes,
like any other name that is not portable (``hi%ED%A0%80``, on every OS). Under
``TRUSTED`` it writes what 7-Zip writes: on POSIX the three-byte UTF-8 form
(``ed a0 80`` for U+D800, as 7-Zip 23.01 does on Linux), on Windows the exact name.

U+DC80-U+DCFF is the exception: in a Python ``str`` that range also means an
undecodable byte (``surrogateescape``), and archivey reads it that way when it
extracts. ``raw_name`` keeps the stored code units for every name.
"""

from __future__ import annotations

import errno
import io
import os
import shutil
import subprocess
import sys
import tarfile
import zlib
from pathlib import Path

import pytest

import archivey
from archivey.cli.exit_codes import EXIT_OK, EXIT_POLICY
from archivey.cli.main import main
from archivey.exceptions import (
    ExtractionError,
    FilterRejectionError,
    LinkTargetNotFoundError,
)
from archivey.internal.filters import apply_name_policy, disk_spelling
from archivey.types import (
    ArchiveMember,
    ExtractionPolicy,
    ExtractionStatus,
    MemberType,
)
from tests.conftest import requires_binary
from tests.extract_util import open_and_extract

_POSIX = sys.platform != "win32"
# APFS refuses a name that is not valid UTF-8 (EILSEQ), so the bytes 7-Zip writes on
# Linux cannot land on the macOS runner's disk.
_BYTE_NAMES = _POSIX and sys.platform != "darwin"


def _u(value: int) -> bytes:
    assert 0 <= value < 0x80
    return bytes([value])


def _prop(prop: int, payload: bytes) -> bytes:
    return bytes([prop]) + _u(len(payload)) + payload


def _surrogate_7z(
    files: list[tuple[str, bytes]], *, comment: str | None = None
) -> bytes:
    """A plain-header 7z with one COPY folder per file and the names as given.

    The names, and the archive ``comment`` when one is given, are encoded with
    ``surrogatepass``, so a lone surrogate is stored as that code unit. Every member
    must have data.
    """
    packed = b"".join(data for _, data in files)
    count = len(files)
    sizes = b"".join(_u(len(data)) for _, data in files)
    crcs = b"".join(
        (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "little") for _, data in files
    )
    pack_info = b"\x06" + _u(0) + _u(count) + b"\x09" + sizes + b"\x00"
    folder = _u(1) + b"\x00"  # one COPY coder
    unpack_info = (
        (b"\x07\x0b" + _u(count) + b"\x00" + folder * count + b"\x0c" + sizes)
        + b"\x0a\x01"
        + crcs
        + b"\x00"
    )
    streams_info = b"\x04" + pack_info + unpack_info + b"\x00"
    names = bytearray(b"\x00")
    for name, _ in files:
        names += name.encode("utf-16le", "surrogatepass") + b"\x00\x00"
    props = _prop(0x11, bytes(names))
    if comment is not None:
        text = comment.encode("utf-16le", "surrogatepass") + b"\x00\x00"
        props += _prop(0x16, b"\x00" + text)  # kComment, not external
    files_info = b"\x05" + _u(count) + props + b"\x00"
    header = b"\x01" + streams_info + files_info + b"\x00"
    start_header = (
        len(packed).to_bytes(8, "little")
        + len(header).to_bytes(8, "little")
        + (zlib.crc32(header) & 0xFFFFFFFF).to_bytes(4, "little")
    )
    return (
        b"7z\xbc\xaf'\x1c\x00\x04"
        + (zlib.crc32(start_header) & 0xFFFFFFFF).to_bytes(4, "little")
        + start_header
        + packed
        + header
    )


_FILES = [
    ("hi\ud800.txt", b"high"),
    ("ok.txt", b"ok"),
    ("z\udfff", b"last"),
    ("dir\udbff/in.txt", b"nested"),
]


@pytest.fixture
def archive(tmp_path: Path) -> Path:
    path = tmp_path / "surrogate.7z"
    path.write_bytes(_surrogate_7z(_FILES))
    return path


def _tree(root: Path) -> dict[bytes, bytes]:
    """Every regular file under ``root`` as its relative path in bytes → contents."""
    out: dict[bytes, bytes] = {}
    broot = os.fsencode(root)
    for dirpath, _dirs, filenames in os.walk(broot):
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            rel = os.path.relpath(full, broot).replace(os.sep.encode(), b"/")
            with open(full, "rb") as f:
                out[rel] = f.read()
    return out


def test_every_member_lists_with_its_surrogate(archive: Path) -> None:
    with archivey.open_archive(archive) as reader:
        members = reader.members()
    assert [m.name for m in members] == [name for name, _ in _FILES]
    assert [m.raw_name for m in members] == [
        name.encode("utf-16le", "surrogatepass") for name, _ in _FILES
    ]


def test_a_member_with_a_surrogate_reads(archive: Path) -> None:
    with archivey.open_archive(archive) as reader:
        assert reader.read("hi\ud800.txt") == b"high"
        assert reader.read("dir\udbff/in.txt") == b"nested"
        assert [(m.name, s.read()) for m, s in reader.stream_members()] == _FILES


_ESCAPED = {
    b"hi%ED%A0%80.txt": b"high",
    b"ok.txt": b"ok",
    b"z%ED%BF%BF": b"last",
    b"dir%ED%AF%BF/in.txt": b"nested",
}


def test_standard_escapes_the_surrogate(archive: Path, tmp_path: Path) -> None:
    """``STANDARD`` escapes the UTF-8 bytes, the same on every OS."""
    dest = tmp_path / "out"
    results = open_and_extract(archive, dest, policy=ExtractionPolicy.STANDARD)
    assert [r.status for r in results] == [ExtractionStatus.EXTRACTED] * len(_FILES)
    assert _tree(dest) == _ESCAPED
    by_name = {r.member.name: r for r in results}
    written = by_name["hi\ud800.txt"]
    assert written.path is not None
    assert written.path.name == "hi%ED%A0%80.txt"
    assert written.presented_name == "hi\ud800.txt"
    assert by_name["ok.txt"].presented_name is None


def test_strict_blocks_a_lone_surrogate(archive: Path, tmp_path: Path) -> None:
    """``STRICT`` refuses a name with a lone surrogate and writes the rest."""
    dest = tmp_path / "out"
    results = open_and_extract(archive, dest, on_error="continue")
    by_name = {r.member.name: r.status for r in results}
    assert by_name.pop("ok.txt") is ExtractionStatus.EXTRACTED
    assert set(by_name.values()) == {ExtractionStatus.BLOCKED}
    assert _tree(dest) == {b"ok.txt": b"ok"}


@pytest.mark.skipif(not _BYTE_NAMES, reason="needs a filesystem that takes any bytes")
def test_trusted_posix_extraction_writes_the_surrogate_as_utf8(
    archive: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "out"
    results = open_and_extract(archive, dest, policy=ExtractionPolicy.TRUSTED)
    assert [r.status for r in results] == [ExtractionStatus.EXTRACTED] * len(_FILES)
    assert _tree(dest) == {
        b"hi\xed\xa0\x80.txt": b"high",
        b"ok.txt": b"ok",
        b"z\xed\xbf\xbf": b"last",
        b"dir\xed\xaf\xbf/in.txt": b"nested",
    }
    by_name = {r.member.name: r for r in results}
    written = by_name["hi\ud800.txt"]
    assert written.path is not None
    assert os.fsencode(written.path.name) == b"hi\xed\xa0\x80.txt"
    # The on-disk spelling is not a rename: the stored name is the name.
    assert written.presented_name is None
    assert written.requested_path == written.path


def _seven_zip_tree(archive: Path, tmp_path: Path) -> dict[bytes, bytes]:
    seven_zip = shutil.which("7z")
    assert seven_zip is not None
    theirs = tmp_path / "theirs"
    theirs.mkdir()
    subprocess.run(
        [seven_zip, "x", "-y", str(archive)],
        cwd=theirs,
        check=True,
        capture_output=True,
    )
    return _tree(theirs)


@pytest.mark.skipif(not _BYTE_NAMES, reason="needs a filesystem that takes any bytes")
@requires_binary("7z")
def test_trusted_posix_extraction_matches_the_7z_tool(
    archive: Path, tmp_path: Path
) -> None:
    """7-Zip 23.01 on Linux writes each lone surrogate as its UTF-8 form."""
    ours = tmp_path / "ours"
    open_and_extract(archive, ours, policy=ExtractionPolicy.TRUSTED)
    assert _tree(ours) == _seven_zip_tree(archive, tmp_path)


@pytest.mark.skipif(not _BYTE_NAMES, reason="needs a filesystem that takes any bytes")
@requires_binary("7z")
def test_standard_escapes_where_the_7z_tool_writes_bytes(
    archive: Path, tmp_path: Path
) -> None:
    """Under ``STANDARD`` every surrogate name differs from 7-Zip's; ok.txt does not."""
    ours = tmp_path / "ours"
    open_and_extract(archive, ours, policy=ExtractionPolicy.STANDARD)
    assert _tree(ours) == _ESCAPED
    assert _seven_zip_tree(archive, tmp_path) == {
        b"hi\xed\xa0\x80.txt": b"high",
        b"ok.txt": b"ok",
        b"z\xed\xbf\xbf": b"last",
        b"dir\xed\xaf\xbf/in.txt": b"nested",
    }


@pytest.mark.skipif(not _BYTE_NAMES, reason="needs a filesystem that takes any bytes")
@requires_binary("7z")
def test_a_unit_in_the_escape_range_is_the_one_difference_from_the_7z_tool(
    tmp_path: Path,
) -> None:
    """U+DC80-U+DCFF: 7-Zip writes its three UTF-8 bytes, archivey the one byte.

    Measured with 7-Zip 23.01 on Linux, against ``TRUSTED``, the policy that otherwise
    writes what 7-Zip writes. archivey writes the byte the unit stands for in a
    ``str``; ``STANDARD`` escapes that byte to ``lo%80.txt``.
    """
    archive = tmp_path / "low.7z"
    archive.write_bytes(_surrogate_7z([*_FILES, ("lo\udc80.txt", b"low")]))
    ours = tmp_path / "ours"
    open_and_extract(archive, ours, policy=ExtractionPolicy.TRUSTED)
    ours_tree, theirs_tree = _tree(ours), _seven_zip_tree(archive, tmp_path)
    assert ours_tree.pop(b"lo\x80.txt") == b"low"
    assert theirs_tree.pop(b"lo\xed\xb2\x80.txt") == b"low"
    assert ours_tree == theirs_tree
    assert len(ours_tree) == len(_FILES)
    default = tmp_path / "default"
    open_and_extract(archive, default, policy=ExtractionPolicy.STANDARD)
    assert _tree(default)[b"lo%80.txt"] == b"low"


@pytest.mark.skipif(sys.platform != "darwin", reason="APFS refuses the bytes")
def test_a_utf8_only_filesystem_refusal_is_a_typed_failure(
    archive: Path, tmp_path: Path
) -> None:
    """On APFS ``TRUSTED``'s bytes are refused: a typed failure, not a crash."""
    dest = tmp_path / "out"
    results = open_and_extract(
        archive, dest, policy=ExtractionPolicy.TRUSTED, on_error="continue"
    )
    by_name = {r.member.name: r for r in results}
    assert by_name["ok.txt"].status is ExtractionStatus.EXTRACTED
    for name in ("hi\ud800.txt", "z\udfff"):
        result = by_name[name]
        if result.status is ExtractionStatus.EXTRACTED:
            continue  # a volume that takes any bytes
        assert result.status is ExtractionStatus.FAILED
        assert isinstance(result.error, ExtractionError)
        cause = result.error.__cause__
        assert isinstance(cause, OSError)
        assert cause.errno == errno.EILSEQ


@pytest.mark.skipif(_POSIX, reason="Windows keeps the exact name")
def test_trusted_windows_extraction_uses_the_exact_name(
    archive: Path, tmp_path: Path
) -> None:
    dest = tmp_path / "out"
    open_and_extract(archive, dest, policy=ExtractionPolicy.TRUSTED)
    assert (dest / "hi\ud800.txt").read_bytes() == b"high"
    assert (dest / "z\udfff").read_bytes() == b"last"
    assert (dest / "dir\udbff" / "in.txt").read_bytes() == b"nested"


@pytest.mark.parametrize(
    ("policy", "written"),
    [
        (ExtractionPolicy.STANDARD, b"hi%ED%A0%80"),
        pytest.param(
            ExtractionPolicy.TRUSTED,
            b"hi\xed\xa0\x80",
            marks=pytest.mark.skipif(
                not _BYTE_NAMES, reason="needs a filesystem that takes any bytes"
            ),
        ),
    ],
)
def test_a_surrogate_name_and_its_utf8_bytes_collide(
    tmp_path: Path, policy: ExtractionPolicy, written: bytes
) -> None:
    """``hi\\ud800`` and a name whose undecodable bytes are ``ed a0 80`` name one file.

    ``STANDARD`` escapes both to ``hi%ED%A0%80`` (``STRICT`` refuses both);
    ``TRUSTED`` writes both as the bytes. The second is resolved by the overwrite policy,
    not written over the first.
    """
    archive = tmp_path / "pair.7z"
    archive.write_bytes(
        _surrogate_7z([("hi\ud800", b"first"), ("hi\udced\udca0\udc80", b"second")])
    )
    dest = tmp_path / "out"
    results = open_and_extract(archive, dest, policy=policy, overwrite="skip")
    assert results[0].status is ExtractionStatus.EXTRACTED
    assert results[1].status is ExtractionStatus.NOT_OVERWRITTEN
    assert _tree(dest) == {written: b"first"}


def test_a_lone_surrogate_in_the_comment_does_not_refuse_the_archive(
    tmp_path: Path,
) -> None:
    """The comment is UTF-16 code units too, and decodes as the names do."""
    archive = tmp_path / "comment.7z"
    archive.write_bytes(_surrogate_7z([("ok.txt", b"ok")], comment="note\ud800"))
    with archivey.open_archive(archive) as reader:
        assert reader.info.comment == "note\ud800"
        assert [m.name for m in reader.members()] == ["ok.txt"]
        assert reader.read("ok.txt") == b"ok"


def test_a_rejection_names_the_stored_member(tmp_path: Path) -> None:
    """The checks see the name that reaches disk; the error reports ``member.name``."""
    archive = tmp_path / "escape.7z"
    archive.write_bytes(_surrogate_7z([("\ud800/../x", b"x"), ("ok.txt", b"ok")]))
    dest = tmp_path / "out"
    results = open_and_extract(archive, dest, on_error="continue")
    blocked, ok = results
    assert ok.status is ExtractionStatus.EXTRACTED
    assert blocked.status is ExtractionStatus.BLOCKED
    assert isinstance(blocked.error, FilterRejectionError)
    assert blocked.error.member_name == blocked.member.name == "\ud800/../x"
    assert "member='\\ud800/../x'" in str(blocked.error)


def test_an_error_while_writing_names_the_member_as_listed(tmp_path: Path) -> None:
    """A write-path error names the member before its disk spelling, under ``TRUSTED``.

    A filter gives a hardlink a lone surrogate, and its target is not in the archive.
    The error is raised after the name checks, by the hardlink write.
    """
    archive = tmp_path / "link.tar"
    with tarfile.open(archive, "w") as tar:
        info = tarfile.TarInfo("h")
        info.type = tarfile.LNKTYPE
        info.linkname = "missing.txt"
        tar.addfile(info)

    def rename(member: ArchiveMember) -> ArchiveMember:
        return member.replace(name=member.name + "\ud800")

    with archivey.open_archive(archive) as reader:
        (result,) = reader.extract_all(
            tmp_path / "out",
            policy=ExtractionPolicy.TRUSTED,
            filter=rename,
            on_error="continue",
        )
    assert isinstance(result.error, LinkTargetNotFoundError)
    assert result.error.member_name == "h\ud800"
    assert result.error.link_target == "missing.txt"


@pytest.mark.skipif(not _BYTE_NAMES, reason="needs a filesystem that takes any bytes")
@pytest.mark.parametrize(
    "links",
    [
        # The source's bytes are written at the failing link: _materialize_orphan_source.
        pytest.param(["h"], id="materialized"),
        # `h1` takes the source's bytes, then `h2` is linked to it: _link_orphan.
        pytest.param(["h1", "h2"], id="linked"),
    ],
)
def test_a_deferred_hardlink_error_names_the_member_as_listed(
    tmp_path: Path, links: list[str]
) -> None:
    """The second pass names a deferred hardlink as the first pass would.

    The filter excludes the source, so its links are deferred to the second pass,
    which writes the source's bytes at the first link and links the rest to it.
    The last link gets a lone surrogate, and its destination is taken, so
    ``OverwritePolicy.ERROR`` fails it there.
    """
    archive = tmp_path / "deferred.tar"
    with tarfile.open(archive, "w") as tar:
        source = tarfile.TarInfo("src")
        source.size = 2
        tar.addfile(source, io.BytesIO(b"ok"))
        for name in links:
            link = tarfile.TarInfo(name)
            link.type = tarfile.LNKTYPE
            link.linkname = "src"
            tar.addfile(link)
    failing = links[-1]

    def rename(member: ArchiveMember) -> ArchiveMember | None:
        if member.name == "src":
            return None
        if member.name == failing:
            return member.replace(name=failing + "\ud800")
        return member

    dest = tmp_path / "out"
    dest.mkdir()
    (dest / os.fsdecode(failing.encode() + b"\xed\xa0\x80")).write_bytes(b"taken")
    with archivey.open_archive(archive) as reader:
        results = reader.extract_all(
            dest,
            policy=ExtractionPolicy.TRUSTED,
            filter=rename,
            on_error="continue",
        )
    (failed,) = [r for r in results if r.member.name == failing]
    assert failed.error is not None
    assert failed.error.member_name == failing + "\ud800"


def _symlinks_tar(path: Path, links: list[tuple[str, str]]) -> None:
    with tarfile.open(path, "w") as tar:
        for name, target in links:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink resolution")
@pytest.mark.parametrize("policy", [ExtractionPolicy.STRICT, ExtractionPolicy.TRUSTED])
@pytest.mark.parametrize(
    "links",
    [
        # Escapes through `d` once created: the check after creating `l` removes it.
        pytest.param([("d", "."), ("l", "d/../s")], id="after-creation"),
        # `a` arrives after `l` and makes it escape: the recheck removes `l`.
        pytest.param([("l", "a/../s"), ("a", ".")], id="recheck"),
    ],
)
def test_a_removed_symlink_names_its_target_as_listed(
    tmp_path: Path, policy: ExtractionPolicy, links: list[tuple[str, str]]
) -> None:
    """The error for a symlink removed after creation names the target before its
    disk spelling, under every policy: O7 does not rewrite link targets."""
    archive = tmp_path / "links.tar"
    _symlinks_tar(archive, links)

    def add_surrogate(member: ArchiveMember) -> ArchiveMember:
        if member.name != "l":
            return member
        return member.replace(link_target=f"{member.link_target}\ud800")

    with archivey.open_archive(archive) as reader:
        results = reader.extract_all(
            tmp_path / "out", policy=policy, filter=add_surrogate, on_error="continue"
        )
    (removed,) = [r for r in results if r.member.name == "l"]
    assert removed.status is ExtractionStatus.BLOCKED
    assert isinstance(removed.error, FilterRejectionError)
    assert removed.error.link_target == dict(links)["l"] + "\ud800"


def test_a_low_surrogate_in_the_escape_range_is_a_byte(tmp_path: Path) -> None:
    """U+DC80-U+DCFF lists as stored, and extracts as the byte it stands for.

    In a ``str`` the unit cannot be told apart from a ``surrogateescape`` byte, so
    extraction treats it as one, as it does for every format: under ``STANDARD`` it is
    written ``%80``. 7-Zip writes ``ed b2 80`` on Linux; ``raw_name`` keeps the unit.
    """
    archive = tmp_path / "low.7z"
    archive.write_bytes(_surrogate_7z([("lo\udc80.txt", b"low")]))
    with archivey.open_archive(archive) as reader:
        (member,) = reader.members()
    assert member.name == "lo\udc80.txt"
    assert member.raw_name == "lo\udc80.txt".encode("utf-16le", "surrogatepass")
    dest = tmp_path / "out"
    (result,) = open_and_extract(archive, dest, policy=ExtractionPolicy.STANDARD)
    assert result.status is ExtractionStatus.EXTRACTED
    assert result.presented_name == "lo\udc80.txt"
    assert (dest / "lo%80.txt").read_bytes() == b"low"


def _run_cli(argv: list[str]) -> tuple[int, str, str]:
    """Run the CLI with strict UTF-8 streams, which raise on a lone surrogate."""
    raw_out, raw_err = io.BytesIO(), io.BytesIO()
    out = io.TextIOWrapper(raw_out, encoding="utf-8", errors="strict")
    err = io.TextIOWrapper(raw_err, encoding="utf-8", errors="strict")
    code = main(argv, out=out, err=err)
    out.flush()
    err.flush()
    return code, raw_out.getvalue().decode(), raw_err.getvalue().decode()


def test_cli_list_escapes_the_surrogate(archive: Path) -> None:
    code, out, _ = _run_cli(["list", str(archive)])
    assert code == EXIT_OK
    assert "hi\\ud800.txt" in out
    assert "z\\udfff" in out
    assert "dir\\udbff/in.txt" in out
    assert "ok.txt" in out


@pytest.mark.parametrize("verb", ["test", "extract"])
def test_cli_member_lines_escape_the_surrogate(
    archive: Path, tmp_path: Path, verb: str
) -> None:
    dest = tmp_path / "out"
    argv = [verb, "-v", str(archive)] + (["-d", str(dest)] if verb == "extract" else [])
    code, out, err = _run_cli(argv)
    assert "hi\\ud800.txt" in out + err
    # The default STRICT refuses the surrogate names: their lines report a block.
    assert code == (EXIT_POLICY if verb == "extract" else EXIT_OK)
    if verb == "extract":
        assert (dest / "ok.txt").read_bytes() == b"ok"


@pytest.mark.parametrize(
    ("name", "posix"),
    [
        ("plain.txt", "plain.txt"),
        ("hi\ud800", "hi\udced\udca0\udc80"),
        ("a\udc7fb", "a\udced\udcb1\udcbfb"),
        ("caf\udce9", "caf\udce9"),  # a surrogateescape byte stays one byte
        ("\U00010000", "\U00010000"),  # a paired surrogate is a character
    ],
)
def test_disk_spelling(name: str, posix: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    assert disk_spelling(name) == posix
    monkeypatch.setattr(sys, "platform", "win32")
    assert disk_spelling(name) == name


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
@pytest.mark.parametrize(
    ("name", "escaped"),
    [
        ("hi\ud800", "hi%ED%A0%80"),
        ("50%\udfff", "50%25%ED%BF%BF"),  # a literal % in a rewritten name is %25
        ("caf\udce9", "caf%E9"),  # a surrogateescape byte stays one byte
        ("\U00010000", "\U00010000"),  # a paired surrogate is a character
    ],
)
def test_the_name_policy_escapes_a_lone_surrogate_on_every_os(
    name: str,
    escaped: str,
    platform: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", platform)
    member = ArchiveMember(
        type=MemberType.FILE,
        name=name,
        raw_name=name.encode("utf-16le", "surrogatepass"),
    )
    assert apply_name_policy(member, ExtractionPolicy.STANDARD).name == escaped
    assert apply_name_policy(member, ExtractionPolicy.TRUSTED).name == name
