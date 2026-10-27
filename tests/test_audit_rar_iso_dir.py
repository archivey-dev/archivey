"""Audit reproducers for the RAR, ISO and directory backends.

Each test states the promised behaviour. A test marked ``xfail(strict=True)`` fails
today for the reason in its marker; it turns green (and so strict-fails) when the bug
is fixed, and the marker must then be removed.

Most archives here are derived from committed fixtures by rewriting headers, so only
``unrar`` is needed at runtime. The helpers rebuild each header with a fresh CRC.
"""

from __future__ import annotations

import contextlib
import dataclasses
import io
import os
import shutil
import struct
import subprocess
import sys
import textwrap
import threading
import zlib
from pathlib import Path
from typing import Any

import pytest

from archivey import ArchiveyConfig, DiagnosticCode, MemberType, open_archive
from archivey.config import DecoderLimits
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    PackageNotInstalledError,
    ResourceLimitError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import rar_reader, rar_unrar
from archivey.internal.backends.rar_parser import parse_rar_archive
from archivey.internal.backends.rar_unar import unar_dictionary_costs
from archivey.internal.external import unar as unar_cli
from tests.conftest import requires_binary

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"
_UNRAR_ONLY = ArchiveyConfig(rar_decompressor="unrar")


def _fixture(name: str) -> Path:
    path = _FIXTURES / name
    if not path.is_file():
        pytest.skip(f"missing vendored fixture {name}")
    return path


# --- RAR5 header rewriting ----------------------------------------------------

_RAR5_SIG = b"Rar!\x1a\x07\x01\x00"


def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        if value:
            out.append(low | 0x80)
        else:
            out.append(low)
            return bytes(out)


def _read_vint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if byte < 0x80:
            return result, pos


def _rar5_parse(data: bytes) -> list[dict[str, Any]]:
    """Split a RAR5 archive into blocks; FILE/SERVICE bodies are decoded field by field."""
    assert data.startswith(_RAR5_SIG)
    pos = len(_RAR5_SIG)
    blocks: list[dict[str, Any]] = []
    while pos < len(data):
        size, body_start = _read_vint(data, pos + 4)
        header = data[body_start : body_start + size]
        q = 0
        block_type, q = _read_vint(header, q)
        flags, q = _read_vint(header, q)
        extra_size = data_size = 0
        if flags & 1:
            extra_size, q = _read_vint(header, q)
        if flags & 2:
            data_size, q = _read_vint(header, q)
        body = header[q : len(header) - extra_size]
        block: dict[str, Any] = {
            "type": block_type,
            "flags": flags,
            "body": body,
            "extra": header[len(header) - extra_size :] if extra_size else b"",
            "data": data[body_start + size : body_start + size + data_size],
        }
        if block_type in (2, 3):
            b = 0
            file_flags, b = _read_vint(body, b)
            unpacked, b = _read_vint(body, b)
            attr, b = _read_vint(body, b)
            mtime = crc = None
            if file_flags & 2:
                mtime = body[b : b + 4]
                b += 4
            if file_flags & 4:
                crc = body[b : b + 4]
                b += 4
            cinfo, b = _read_vint(body, b)
            host_os, b = _read_vint(body, b)
            name_len, b = _read_vint(body, b)
            block.update(
                file_flags=file_flags,
                unpacked=unpacked,
                attr=attr,
                mtime=mtime,
                crc=crc,
                cinfo=cinfo,
                host_os=host_os,
                name=body[b : b + name_len],
            )
        blocks.append(block)
        pos = body_start + size + data_size
    return blocks


def _rar5_build(blocks: list[dict[str, Any]]) -> bytes:
    out = bytearray(_RAR5_SIG)
    for block in blocks:
        if "file_flags" in block:
            file_flags = block["file_flags"] & ~6
            if block["mtime"] is not None:
                file_flags |= 2
            if block["crc"] is not None:
                file_flags |= 4
            body = _vint(file_flags) + _vint(block["unpacked"]) + _vint(block["attr"])
            if block["mtime"] is not None:
                body += block["mtime"]
            if block["crc"] is not None:
                body += block["crc"]
            body += (
                _vint(block["cinfo"])
                + _vint(block["host_os"])
                + _vint(len(block["name"]))
                + block["name"]
            )
        else:
            body = block["body"]
        flags = block["flags"] & ~3
        if block["extra"]:
            flags |= 1
        if block["data"] or block["flags"] & 2:
            flags |= 2
        header = _vint(block["type"]) + _vint(flags)
        if flags & 1:
            header += _vint(len(block["extra"]))
        if flags & 2:
            header += _vint(len(block["data"]))
        header += body + block["extra"]
        sized = _vint(len(header)) + header
        out += struct.pack("<I", zlib.crc32(sized)) + sized + block["data"]
    return bytes(out)


def _rar5_file_blocks(blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [block for block in blocks if block["type"] == 2]


def _hostile_argv_payloads() -> dict[str, bytes]:
    """Member data of ``hostile_argv__.rar``, read through the untouched fixture."""
    with open_archive(_fixture("hostile_argv__.rar"), config=_UNRAR_ONLY) as archive:
        return {member.name: archive.read(member) for member in archive.members()}


# --- RAR3 header rewriting ----------------------------------------------------

_RAR3_SIG = b"Rar!\x1a\x07\x00"


def _rar3_parse(data: bytes) -> list[dict[str, Any]]:
    assert data.startswith(_RAR3_SIG)
    pos = len(_RAR3_SIG)
    blocks: list[dict[str, Any]] = []
    while pos + 7 <= len(data):
        _crc, block_type, flags, size = struct.unpack_from("<HBHH", data, pos)
        add = 0
        if flags & 0x8000 or block_type == 0x74:
            add = struct.unpack_from("<I", data, pos + 7)[0]
        blocks.append(
            {
                "type": block_type,
                "header": bytearray(data[pos : pos + size]),
                "data": data[pos + size : pos + size + add],
            }
        )
        pos += size + add
    return blocks


def _rar3_rename(block: dict[str, Any], name: bytes, *, extra_flags: int = 0) -> None:
    """Replace a FILE header's name; clear the Unicode flag and OR in ``extra_flags``."""
    header = block["header"]
    flags = struct.unpack_from("<H", header, 3)[0]
    old_len = struct.unpack_from("<H", header, 26)[0]
    offset = 32 + (8 if flags & 0x100 else 0)
    header[offset : offset + old_len] = name
    struct.pack_into("<H", header, 26, len(name))
    flags = (flags & ~0x0200) | extra_flags
    struct.pack_into("<H", header, 3, flags)
    struct.pack_into("<H", header, 5, len(header))


def _rar3_build(blocks: list[dict[str, Any]]) -> bytes:
    out = bytearray(_RAR3_SIG)
    for block in blocks:
        header = block["header"]
        struct.pack_into("<H", header, 0, zlib.crc32(bytes(header[2:])) & 0xFFFF)
        out += header + block["data"]
    return bytes(out)


def _renamed_rar4_hostile(tmp_path: Path, name: bytes, *, extra_flags: int = 0) -> Path:
    blocks = _rar3_parse(_fixture("hostile_argv__rar4.rar").read_bytes())
    first_file = next(block for block in blocks if block["type"] == 0x74)
    _rar3_rename(first_file, name, extra_flags=extra_flags)
    path = tmp_path / "renamed_rar4.rar"
    path.write_bytes(_rar3_build(blocks))
    return path


# --- multi-volume: an explicit path sequence ---------------------------------


def test_explicit_rar_volume_paths_in_separate_directories_open(
    tmp_path: Path,
) -> None:
    """docs/opening.md: pass the volumes yourself when they are not siblings.

    "Do that and the order you give is the order used, with no discovery." The
    RAR branch of ``open_archive`` replaces the joined source with volume 1's path
    and rediscovers siblings beside it, so the second volume in another directory
    is never seen.
    """
    parts = []
    for index in (1, 2):
        folder = tmp_path / f"disk{index}"
        folder.mkdir()
        dest = folder / f"tinyvol.part{index}.rar"
        shutil.copyfile(_fixture(f"tinyvol.part{index}.rar"), dest)
        parts.append(dest)
    with open_archive(parts) as archive:
        names = [member.name for member in archive.members()]
    assert names == ["payload.bin"]


# --- the unrar -n include mask addresses by name ----------------------------


@requires_binary("unrar")
def test_duplicate_named_compressed_rar5_members_read_their_own_bytes(
    tmp_path: Path,
) -> None:
    """A valid archive whose later entry repeats a name (unrar t: All OK).

    ``unrar p -n./-inul`` emits both entries, in archive order; each read skips
    to its own.
    """
    payloads = _hostile_argv_payloads()
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    files = _rar5_file_blocks(blocks)
    files[2]["name"] = files[1]["name"]  # "@atfile" -> "-inul"
    path = tmp_path / "dup.rar"
    path.write_bytes(_rar5_build(blocks))

    with open_archive(path, config=_UNRAR_ONLY) as archive:
        members = archive.members()
        assert [m.name for m in members] == ["canary.txt", "-inul", "-inul"]
        assert archive.read(members[2]) == payloads["@atfile"]
        assert archive.read(members[1]) == payloads["-inul"]


@requires_binary("unrar")
@pytest.mark.parametrize(
    ("attr", "unrar_reads_it"),
    [
        (0o020664, True),
        # A vint wider than a C unsigned long, which stat.S_IFMT would refuse. unrar
        # misreads the rest of that header, so only the listing is checked.
        ((1 << 70) | 0o020664, False),
    ],
)
def test_unix_special_file_with_data_is_a_file(
    tmp_path: Path, attr: int, unrar_reads_it: bool
) -> None:
    """A Unix-host entry whose mode names a device but that stores data is a FILE:
    the data stream is the structure, the mode only an attribute (DR-25). The mode
    survives in ``extra["special_file_type"]`` and an advisory diagnostic says so.

    rar skips devices when archiving, so the mode is written into a fixture's header.
    """
    payloads = _hostile_argv_payloads()
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    files = _rar5_file_blocks(blocks)
    assert files[1]["host_os"] == 1  # Unix
    files[1]["attr"] = attr  # char device
    path = tmp_path / "device.rar"
    path.write_bytes(_rar5_build(blocks))

    with open_archive(path, config=_UNRAR_ONLY) as archive:
        members = archive.members()
        assert [m.type for m in members] == [MemberType.FILE] * 3
        assert members[1].size == len(payloads["-inul"])
        assert members[1].extra["special_file_type"] == "char_device"
        assert "special_file_type" not in members[0].extra
        if unrar_reads_it:
            assert archive.read(members[1]) == payloads["-inul"]
        assert archive.read(members[2]) == payloads["@atfile"]
        diags = [
            d
            for d in archive.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA
        ]
        assert len(diags) == 1
        assert diags[0].context is not None
        assert diags[0].context.to_dict() == {
            "kind": "special_file_data",
            "archive_name": str(path),
            "member_name": "-inul",
            "member_id": 1,
            "special_file_type": "char_device",
            "size": len(payloads["-inul"]),
        }
        if unrar_reads_it:
            archive.extract_all(tmp_path / "out")
            assert (tmp_path / "out" / "-inul").read_bytes() == payloads["-inul"]
            assert (tmp_path / "out" / "@atfile").read_bytes() == payloads["@atfile"]


@requires_binary("rar")
@requires_binary("unrar")
def test_file_copy_with_a_special_mode_keeps_its_kind(tmp_path: Path) -> None:
    """A RAR5 file copy (``rar -oi``) is typed FILE by its redirect record, so the
    data-based rule never runs for it; ``extra["special_file_type"]`` still records
    what its mode said, and the advisory diagnostic reports the data it names."""
    src = tmp_path / "src"
    src.mkdir()
    payload = b"".join(b"line %05d of the copied file\n" % i for i in range(200))
    (src / "r1.bin").write_bytes(payload)
    (src / "r2.bin").write_bytes(payload)
    built = tmp_path / "copies.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-ep1", "-oi:1000", str(built), "r1.bin", "r2.bin"],
        cwd=src,
        check=True,
        timeout=60,
    )
    blocks = _rar5_parse(built.read_bytes())
    files = _rar5_file_blocks(blocks)
    copy = next(block for block in files if block["name"] == b"r2.bin")
    assert copy["host_os"] == 1 and copy["data"] == b""  # Unix; a redirect, no data
    copy["attr"] = 0o010644  # FIFO
    path = tmp_path / "fifo-copy.rar"
    path.write_bytes(_rar5_build(blocks))

    with open_archive(path, config=_UNRAR_ONLY) as archive:
        member = archive.get("r2.bin")
        assert member.type is MemberType.FILE
        assert member.extra["is_file_copy"] is True
        assert member.extra["special_file_type"] == "fifo"
        assert "special_file_type" not in archive.get("r1.bin").extra
        assert archive.read(member) == payload
        [diag] = [
            d
            for d in member.diagnostics
            if d.code is DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA
        ]
        assert diag.context is not None
        assert diag.context.to_dict()["special_file_type"] == "fifo"
        assert diag.context.to_dict()["size"] == len(payload)


@requires_binary("unrar")
def test_file_copy_built_from_a_hardlink_record_keeps_its_kind(tmp_path: Path) -> None:
    """The same shape as the live ``rar -oi`` test, built from a committed fixture so
    it runs where CI has only ``unrar``: a RAR5 ``HARD_LINK`` redirect record differs
    from a ``FILE_COPY`` one by its redirect type alone, so the hard link in
    ``hardlinks_solid__.rar`` becomes a file copy with one byte changed."""
    blocks = _rar5_parse(_fixture("hardlinks_solid__.rar").read_bytes())
    files = _rar5_file_blocks(blocks)
    link = next(b for b in files if b["name"] == b"subdir/hardlink_to_file1.txt")
    assert link["host_os"] == 1 and link["data"] == b""  # Unix; a redirect, no data
    # REDIR extra record: size, type 5 (REDIR), redirect type 4 (HARD_LINK), flags,
    # name length, name. Redirect type 5 is FILE_COPY.
    redir = b"\x0d\x05\x04\x00\x09file1.txt"
    assert link["extra"].count(redir) == 1
    link["extra"] = link["extra"].replace(redir, b"\x0d\x05\x05\x00\x09file1.txt")
    link["attr"] = 0o010644  # FIFO
    path = tmp_path / "fifo-copy.rar"
    path.write_bytes(_rar5_build(blocks))

    with open_archive(path, config=_UNRAR_ONLY) as archive:
        member = archive.get("subdir/hardlink_to_file1.txt")
        assert member.type is MemberType.FILE
        assert member.extra["is_file_copy"] is True
        assert member.extra["special_file_type"] == "fifo"
        assert "special_file_type" not in archive.get("file1.txt").extra
        assert archive.read(member) == archive.read("file1.txt") == b"Hello 1!"
        [diag] = [
            d
            for d in member.diagnostics
            if d.code is DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA
        ]
        assert diag.context is not None
        assert diag.context.to_dict()["special_file_type"] == "fifo"
        assert diag.context.to_dict()["size"] == 8


@requires_binary("unrar")
def test_unix_special_file_without_data_is_other(tmp_path: Path) -> None:
    """A device-mode entry with no data is OTHER, as in TAR, 7z and ISO: there is
    nothing to read, and extraction skips it instead of creating an empty file."""
    payloads = _hostile_argv_payloads()
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    files = _rar5_file_blocks(blocks)
    assert files[1]["host_os"] == 1  # Unix
    files[1]["attr"] = 0o010664  # FIFO
    files[1]["data"] = b""
    files[1]["unpacked"] = 0
    files[1]["crc"] = struct.pack("<I", zlib.crc32(b""))
    files[1]["flags"] &= ~2
    path = tmp_path / "fifo.rar"
    path.write_bytes(_rar5_build(blocks))

    with open_archive(path, config=_UNRAR_ONLY) as archive:
        members = archive.members()
        assert [m.type for m in members] == [
            MemberType.FILE,
            MemberType.OTHER,
            MemberType.FILE,
        ]
        assert members[1].extra["special_file_type"] == "fifo"
        codes = [d.code for d in archive.diagnostics.retained]
        assert DiagnosticCode.MEMBER_SPECIAL_FILE_HAS_DATA not in codes
        assert archive.read(members[2]) == payloads["@atfile"]
        archive.extract_all(tmp_path / "out")
    assert not (tmp_path / "out" / "-inul").exists()
    assert (tmp_path / "out" / "@atfile").read_bytes() == payloads["@atfile"]


@requires_binary("unrar")
def test_invalid_utf8_name_never_reads_a_siblings_bytes(tmp_path: Path) -> None:
    """Bytes returned for a member must be that member's bytes.

    The target has no stored digest (RAR5 makes the CRC optional), so nothing
    downstream notices. ``unrar`` itself sees the invalid name as empty, and
    ``rar_decompressor='unar'`` (which addresses entries by index) reads it right.
    """
    payloads = _hostile_argv_payloads()
    assert len(payloads["-inul"]) == len(payloads["@atfile"])
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    files = _rar5_file_blocks(blocks)
    files[1]["name"] = b"\xff"  # "-inul": not UTF-8
    files[1]["crc"] = None
    files[2]["name"] = "�".encode()  # "@atfile": literally U+FFFD
    path = tmp_path / "fffd.rar"
    path.write_bytes(_rar5_build(blocks))

    with open_archive(path, config=_UNRAR_ONLY) as archive:
        target = archive.members()[1]
        assert target.hashes == {}
        try:
            data = archive.read(target)
        except ArchiveyError:
            return  # refusing is acceptable; the sibling's bytes are not
    assert data != payloads["@atfile"]
    assert data == payloads["-inul"]


_C_LOCALE_READ = textwrap.dedent(
    """
    import sys
    from archivey import ArchiveyConfig, open_archive
    config = ArchiveyConfig(rar_decompressor="unrar")
    with open_archive(sys.argv[1], config=config) as archive:
        member = archive.members()[0]
        sys.stdout.buffer.write(archive.read(member))
    """
)


@requires_binary("unrar")
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX locale behaviour")
def test_non_ascii_member_reads_under_the_c_locale(tmp_path: Path) -> None:
    """``LC_ALL=C`` is common in cron jobs, CI and containers; the archive is valid.

    Python coerces a bare C locale for its children, but an explicit ``LC_ALL``
    (or a ``LANG`` naming a missing locale) turns that off, and archivey passes the
    environment through unchanged.
    """
    payloads = _hostile_argv_payloads()
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    _rar5_file_blocks(blocks)[0]["name"] = "cañary.txt".encode()
    path = tmp_path / "accent.rar"
    path.write_bytes(_rar5_build(blocks))

    env = {**os.environ, "LC_ALL": "C"}
    env.pop("PYTHONUTF8", None)
    completed = subprocess.run(
        [sys.executable, "-c", _C_LOCALE_READ, str(path)],
        capture_output=True,
        env=env,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")[-400:]
    assert completed.stdout == payloads["canary.txt"]


@requires_binary("unrar")
def test_rar3_8bit_name_member_is_readable(tmp_path: Path) -> None:
    """A RAR 2.x/3.x name without the Unicode flag, in a single-byte code page.

    ``unrar`` maps the stored bytes through the locale; archivey decodes them as
    windows-1252 and hands ``unrar`` the UTF-8 of that. Nine bytes, so the
    UTF-16 misdecode (next test) does not apply.
    """
    with open_archive(_fixture("hostile_argv__rar4.rar"), config=_UNRAR_ONLY) as ar:
        expected = ar.read("canary.txt")
    path = _renamed_rar4_hostile(tmp_path, b"caf\xe9s.txt")
    with open_archive(path, config=_UNRAR_ONLY) as archive:
        member = archive.members()[0]
        assert member.name == "cafés.txt"
        assert archive.read(member) == expected


def test_rar3_8bit_name_is_not_decoded_as_utf16(tmp_path: Path) -> None:
    """``caf\\xe9.txt`` is eight bytes; it must not list as ``'慣\\ue966琮瑸'``."""
    path = _renamed_rar4_hostile(tmp_path, b"caf\xe9.txt")
    with open_archive(path) as archive:
        member = archive.members()[0]
        # The fixture was written on Unix, so the fallback is windows-1252.
        assert member.name == "café.txt"
        assert member.raw_name == b"caf\xe9.txt"
    with open_archive(path, encoding="cp437") as archive:
        member = archive.members()[0]
        assert member.name == "cafΘ.txt"
        assert member.raw_name == b"caf\xe9.txt"


# --- non-ArchiveyError exceptions --------------------------------------------


@pytest.mark.parametrize(
    "suffix",
    ["²".encode(), b"1" * 5000],
    ids=["superscript-two", "5000-digits"],
)
def test_rar3_version_suffix_is_parsed_without_a_bare_value_error(
    tmp_path: Path, suffix: bytes
) -> None:
    """``open_archive`` on crafted input raises an ``ArchiveyError`` or succeeds."""
    path = _renamed_rar4_hostile(tmp_path, b"a;" + suffix, extra_flags=0x0800)
    try:
        with open_archive(path) as archive:
            archive.members()
    except ArchiveyError:
        pass


@requires_binary("unrar")
def test_nul_in_member_name_read_raises_an_archivey_error(tmp_path: Path) -> None:
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    _rar5_file_blocks(blocks)[0]["name"] = b"nul\x00x.txt"
    path = tmp_path / "nul.rar"
    path.write_bytes(_rar5_build(blocks))
    with open_archive(path, config=_UNRAR_ONLY) as archive:
        member = archive.members()[0]
        with pytest.raises(ArchiveyError):
            archive.read(member)


# --- passwords on unrar's stdin ----------------------------------------------


@requires_binary("unrar")
def test_password_with_nul_is_not_silently_cut_by_unrar() -> None:
    """``_password_stdin_bytes`` refuses a line break for this reason; NUL is the same.

    RAR3/4 data has no password check value, so the member's CRC is the only
    judge, and it passes because ``unrar`` used ``password``.
    """
    with open_archive(
        _fixture("encryption__rar4.rar"),
        password="password\x00zz",
        config=_UNRAR_ONLY,
    ) as archive:
        member = archive.members()[0]
        with pytest.raises(ArchiveyError):
            archive.read(member)


@requires_binary("rar", "unrar")
def test_long_password_does_not_deadlock_the_unrar_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RAR5 hashes only the first 127 characters, so this password is the right one.

    The PswCheck accepts it natively. Written whole to ``unrar``'s stdin before
    stdout is read, 200 KB fills the pipe while ``unrar`` fills stdout with the
    300 KB member, and both processes wait on each other. The read runs in a
    thread; after the deadline the test kills ``unrar`` to unblock it.
    """
    source = tmp_path / "rnd.bin"
    source.write_bytes(os.urandom(300_000))
    archive_path = tmp_path / "enc.rar"
    subprocess.run(
        [
            "rar",
            "a",
            "-idq",
            "-m1",
            "-ep",
            "-p" + "p" * 127,
            str(archive_path),
            str(source),
        ],
        check=True,
        timeout=30,
    )
    spawned: list[subprocess.Popen[bytes]] = []
    real_spawn = rar_unrar.spawn_for_stdout

    def recording_spawn(*args: Any, **kwargs: Any) -> Any:
        proc, stdout = real_spawn(*args, **kwargs)
        spawned.append(proc)
        return proc, stdout

    monkeypatch.setattr(rar_unrar, "spawn_for_stdout", recording_spawn)
    outcome: list[object] = []

    def read() -> None:
        try:
            with open_archive(
                archive_path, password="p" * 127 + "x" * 200_000, config=_UNRAR_ONLY
            ) as archive:
                outcome.append(archive.read(archive.members()[0]))
        except BaseException as exc:  # noqa: BLE001 - reported below
            outcome.append(exc)

    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    worker.join(timeout=2.0)
    finished = not worker.is_alive()
    for proc in spawned:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    worker.join(timeout=10)
    assert finished, "archive.read() was still blocked in open_unrar_p after 2.0 s"
    assert outcome and outcome[0] == source.read_bytes()


# --- the RAR dictionary counts against DecoderLimits.max_decoder_memory ------
#
# The rule differs by program (dev-docs/formats/rar.md section 7). unar writes to the
# whole declared dictionary, so the declared size counts. unrar fills pages only as it
# writes output, so it counts the declared size capped at the unpacked bytes it
# decodes: the member's own size, or in a solid archive everything up to the member.

_RAR5_DICT_4GIB = 15  # 128 KiB << 15
_DEFAULT_LIMIT = DecoderLimits().max_decoder_memory
_3_GIB = 3 * 2**30


def _declare_dictionary(
    block: dict[str, Any], exponent: int, unpacked: int | None = None
) -> None:
    """Make a parsed FILE ``block`` declare a ``128 KiB << exponent`` dictionary.

    With ``unpacked``, it also declares that unpacked size. The data is not changed,
    so only a read refused before ``unrar`` or ``unar`` starts can use the result.
    """
    assert (block["cinfo"] >> 7) & 7, "a stored member never reaches the check"
    block["cinfo"] = (block["cinfo"] & ~(0x3FF << 10)) | (exponent << 10)
    if unpacked is not None:
        block["unpacked"] = unpacked


def _declaring_dictionary(
    tmp_path: Path,
    fixture: str,
    index: int,
    exponent: int,
    unpacked: int | None = None,
) -> Path:
    """``fixture`` with FILE header ``index`` declaring a ``128 KiB << exponent`` dictionary."""
    blocks = _rar5_parse(_fixture(fixture).read_bytes())
    _declare_dictionary(_rar5_file_blocks(blocks)[index], exponent, unpacked)
    path = tmp_path / f"dict{exponent}_{unpacked}_{fixture}"
    path.write_bytes(_rar5_build(blocks))
    return path


def _config(program: str, max_decoder_memory: int | None = None) -> ArchiveyConfig:
    if max_decoder_memory is None:
        return ArchiveyConfig(rar_decompressor=program)
    return ArchiveyConfig(
        rar_decompressor=program,
        decoder_limits=DecoderLimits(max_decoder_memory=max_decoder_memory),
    )


@pytest.fixture
def no_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if a refused read starts unrar or unar anyway."""

    def refuse(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a decompressor was spawned for a refused read")

    monkeypatch.setattr(rar_unrar, "spawn_for_stdout", refuse)
    monkeypatch.setattr(unar_cli, "spawn_for_stdout", refuse)


def _stream_all(path: Path, config: ArchiveyConfig) -> dict[str, bytes]:
    # Closed before the archive is, also when a read raises.
    with (
        open_archive(path, config=config) as archive,
        contextlib.closing(archive.stream_members()) as members,
    ):
        return {
            member.name: stream.read()
            for member, stream in members
            if stream is not None
        }


@requires_binary("unrar")
def test_unrar_reads_a_small_nonsolid_member_declaring_4_gib(tmp_path: Path) -> None:
    """unrar sizes the window to the 1408-byte member, so 4 GiB declared is allowed."""
    expected = _hostile_argv_payloads()["canary.txt"]
    path = _declaring_dictionary(tmp_path, "hostile_argv__.rar", 0, _RAR5_DICT_4GIB)
    with open_archive(path, config=_UNRAR_ONLY) as archive:
        assert archive.read("canary.txt") == expected


@requires_binary("unar")
def test_unar_refuses_a_small_nonsolid_member_declaring_4_gib(
    tmp_path: Path, no_spawn: None
) -> None:
    """unar writes to the whole declared dictionary, whatever the member's size."""
    path = _declaring_dictionary(tmp_path, "hostile_argv__.rar", 0, _RAR5_DICT_4GIB)
    with (
        open_archive(path, config=_config("unar")) as archive,
        pytest.raises(ResourceLimitError, match="max_decoder_memory"),
    ):
        archive.read("canary.txt")


@requires_binary("unrar")
def test_unrar_refuses_a_nonsolid_member_over_a_lowered_limit(
    tmp_path: Path, no_spawn: None
) -> None:
    """The cap is the unpacked size: 1408 bytes is over a 1 KiB limit."""
    path = _declaring_dictionary(tmp_path, "hostile_argv__.rar", 0, _RAR5_DICT_4GIB)
    with (
        open_archive(path, config=_config("unrar", 1024)) as archive,
        pytest.raises(ResourceLimitError, match="max_decoder_memory=1024"),
    ):
        archive.read("canary.txt")


@requires_binary("unrar")
def test_unrar_refuses_a_nonsolid_member_declaring_4_gib_and_3_gib_by_default(
    tmp_path: Path, no_spawn: None
) -> None:
    """The one shape the default refuses under unrar: a big dictionary and big data.

    unrar counts the smaller of the two, 3 GiB, over the 2 GiB default. The message
    gives the declared 4 GiB as well, so it does not call 3 GiB the declared size.
    """
    path = _declaring_dictionary(
        tmp_path, "hostile_argv__.rar", 0, _RAR5_DICT_4GIB, unpacked=_3_GIB
    )
    with (
        open_archive(path, config=_UNRAR_ONLY) as archive,
        pytest.raises(
            ResourceLimitError, match=f"max_decoder_memory={_DEFAULT_LIMIT}"
        ) as excinfo,
    ):
        archive.read("canary.txt")
    message = str(excinfo.value)
    assert (
        f"is {_3_GIB} bytes, counted from the {4 * 2**30}-byte dictionary its own "
        "header declares, capped at the unpacked bytes the read decodes"
    ) in message


@requires_binary("unrar")
def test_unrar_refuses_a_solid_member_behind_a_big_declared_prefix_by_default(
    tmp_path: Path, no_spawn: None
) -> None:
    """``tail.txt`` is 12 bytes, but the member ahead of it declares 4 GiB and 3 GiB."""
    path = _declaring_dictionary(
        tmp_path, "seek_respawn_solid__.rar", 0, _RAR5_DICT_4GIB, unpacked=_3_GIB
    )
    with (
        open_archive(path, config=_UNRAR_ONLY) as archive,
        pytest.raises(
            ResourceLimitError, match=f"max_decoder_memory={_DEFAULT_LIMIT}"
        ) as excinfo,
    ):
        archive.read("tail.txt")
    # tail.txt's own header declares a different dictionary: the numbers are
    # prefix.bin's, and the message says so.
    assert (
        f"member 'tail.txt' is {_3_GIB + 12} bytes, counted from the {4 * 2**30}-byte "
        "dictionary the header of member 'prefix.bin' declares, capped at the "
        "unpacked bytes the read decodes"
    ) in str(excinfo.value)
    with pytest.raises(
        ResourceLimitError, match=f"max_decoder_memory={_DEFAULT_LIMIT}"
    ) as excinfo:
        _stream_all(path, _UNRAR_ONLY)
    # The pass stops at prefix.bin, whose own header declares the dictionary.
    assert (
        f"member 'prefix.bin' is {_3_GIB} bytes, counted from the {4 * 2**30}-byte "
        "dictionary its own header declares"
    ) in str(excinfo.value)


def test_a_stored_solid_member_is_sliced_without_paying_the_window_ahead(
    tmp_path: Path, no_spawn: None
) -> None:
    """A stored member is sliced out of the archive, solid flag or not.

    ``rar -s`` writes this shape for any file it stores. Here ``tail.txt`` is marked
    stored, and ``prefix.bin`` ahead of it declares 4 GiB and 3 GiB unpacked. unrar
    would decode that prefix to reach the tail; the reader starts no program, so the
    window is not charged. The tail's bytes are still the compressed ones, which its
    CRC rejects.
    """
    blocks = _rar5_parse(_fixture("seek_respawn_solid__.rar").read_bytes())
    prefix, tail = _rar5_file_blocks(blocks)
    _declare_dictionary(prefix, _RAR5_DICT_4GIB, unpacked=_3_GIB)
    tail["cinfo"] &= ~(7 << 7)  # method 0, stored; the solid flag stays
    path = tmp_path / "stored_tail.rar"
    path.write_bytes(_rar5_build(blocks))
    with (
        open_archive(path, config=_UNRAR_ONLY) as archive,
        pytest.raises(CorruptionError, match="crc32"),
    ):
        archive.read("tail.txt")
    # unar does not decode the stream ahead of a stored member (measured, rar.md 7).
    with path.open("rb") as f:
        assert unar_dictionary_costs(parse_rar_archive(f))[1] == (0, -1)


@requires_binary("unrar")
def test_unrar_counts_the_window_ahead_of_an_encrypted_stored_solid_member(
    tmp_path: Path, no_spawn: None
) -> None:
    """An encrypted stored member is not sliced, so unrar reads it and pays the window.

    unrar decodes the solid prefix to reach it. The archive is the one above with
    ``tail.txt`` also carrying an encryption record; the read is refused on the
    dictionary before unrar starts, with or without a password.
    """
    blocks = _rar5_parse(_fixture("seek_respawn_solid__.rar").read_bytes())
    prefix, tail = _rar5_file_blocks(blocks)
    _declare_dictionary(prefix, _RAR5_DICT_4GIB, unpacked=_3_GIB)
    tail["cinfo"] &= ~(7 << 7)  # method 0, stored; the solid flag stays
    # FHEXTRA_CRYPT: version 0, no password check, KDF count 15, salt, IV.
    record = _vint(1) + _vint(0) + _vint(0) + bytes([15]) + bytes(16) + bytes(16)
    tail["extra"] += _vint(len(record)) + record
    path = tmp_path / "encrypted_stored_tail.rar"
    path.write_bytes(_rar5_build(blocks))
    with open_archive(path, config=_UNRAR_ONLY, password="password") as archive:
        member = archive.get("tail.txt")
        assert member is not None
        assert member.is_encrypted
        with pytest.raises(
            ResourceLimitError, match=f"max_decoder_memory={_DEFAULT_LIMIT}"
        ) as excinfo:
            archive.read("tail.txt")
    assert "the header of member 'prefix.bin' declares" in str(excinfo.value)


@requires_binary("unrar")
def test_unrar_counts_an_earlier_member_its_shared_mask_decodes(
    tmp_path: Path, no_spawn: None
) -> None:
    """A duplicate name makes unrar decode the earlier entry before the target.

    The archive is not solid, so the earlier entry sizes its own window: 4 GiB
    declared and 3 GiB unpacked. The target itself is 1216 bytes, well under the
    default, and reading it is still refused.
    """
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    files = _rar5_file_blocks(blocks)
    _declare_dictionary(files[1], _RAR5_DICT_4GIB, unpacked=_3_GIB)
    files[2]["name"] = files[1]["name"]  # "@atfile" -> "-inul"
    path = tmp_path / "dup_dict.rar"
    path.write_bytes(_rar5_build(blocks))

    with open_archive(path, config=_UNRAR_ONLY) as archive:
        members = archive.members()
        assert [m.name for m in members] == ["canary.txt", "-inul", "-inul"]
        assert members[2].size == 1216
        with pytest.raises(
            ResourceLimitError, match=f"max_decoder_memory={_DEFAULT_LIMIT}"
        ) as excinfo:
            archive.read(members[2])
    # Both entries are named "-inul", so the declarer is named by its index.
    assert (
        f"member '-inul' is {_3_GIB} bytes, counted from the {4 * 2**30}-byte "
        "dictionary the header of an earlier entry with the same name (archive index "
        "1, counting from 0) declares, capped at the unpacked bytes the read decodes"
    ) in str(excinfo.value)


@requires_binary("unrar")
def test_unrar_reads_a_small_solid_archive_whose_first_member_declares_4_gib(
    tmp_path: Path,
) -> None:
    """unrar keeps the 4 GiB window for the stream, but writes only 1 MiB into it."""
    fixture = "seek_respawn_solid__.rar"
    expected = _stream_all(_fixture(fixture), _UNRAR_ONLY)
    path = _declaring_dictionary(tmp_path, fixture, 0, _RAR5_DICT_4GIB)
    with open_archive(path, config=_UNRAR_ONLY) as archive:
        assert archive.read("tail.txt") == expected["tail.txt"]
    assert _stream_all(path, _UNRAR_ONLY) == expected


@requires_binary("unar")
def test_unar_refuses_every_member_of_a_solid_stream_declaring_4_gib(
    tmp_path: Path, no_spawn: None
) -> None:
    """Only the first header declares 4 GiB; unar allocates it for the whole stream."""
    path = _declaring_dictionary(
        tmp_path, "seek_respawn_solid__.rar", 0, _RAR5_DICT_4GIB
    )
    config = _config("unar")
    with open_archive(path, config=config) as archive:
        for name in ("prefix.bin", "tail.txt"):
            with pytest.raises(ResourceLimitError, match="max_decoder_memory"):
                archive.read(name)
        with pytest.raises(ResourceLimitError) as excinfo:
            archive.read("tail.txt")
    # unar's count is the declared size, and it is prefix.bin's header that declares it.
    # The count is the declared size, so the number is not given twice.
    assert (
        f"for member 'tail.txt' is {4 * 2**30} bytes, counted from the "
        "dictionary the header of member 'prefix.bin' declares)"
    ) in str(excinfo.value)
    with pytest.raises(ResourceLimitError, match="max_decoder_memory"):
        _stream_all(path, config)


@requires_binary("unrar")
def test_unrar_refuses_a_solid_member_whose_decoded_prefix_is_over_the_limit(
    tmp_path: Path, no_spawn: None
) -> None:
    """``tail.txt`` is 12 bytes, but reading it decodes the 1 MiB ``prefix.bin`` first."""
    path = _declaring_dictionary(
        tmp_path, "seek_respawn_solid__.rar", 0, _RAR5_DICT_4GIB
    )
    config = _config("unrar", 512 * 1024)
    with (
        open_archive(path, config=config) as archive,
        pytest.raises(ResourceLimitError, match="max_decoder_memory=524288"),
    ):
        archive.read("tail.txt")
    with pytest.raises(ResourceLimitError, match="max_decoder_memory=524288"):
        _stream_all(path, config)


@requires_binary("unrar")
def test_unrar_solid_count_is_capped_at_the_decoded_bytes(tmp_path: Path) -> None:
    """4 GiB declared, about 1 MiB decoded: a 2 MiB limit is enough."""
    fixture = "seek_respawn_solid__.rar"
    expected = _stream_all(_fixture(fixture), _UNRAR_ONLY)
    path = _declaring_dictionary(tmp_path, fixture, 0, _RAR5_DICT_4GIB)
    assert _stream_all(path, _config("unrar", 2 * 2**20)) == expected


@requires_binary("unrar", "unar")
@pytest.mark.parametrize("unrar_found", [True, False], ids=["unrar", "unar"])
def test_auto_counts_for_the_program_it_picks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unrar_found: bool
) -> None:
    expected = _hostile_argv_payloads()["canary.txt"]
    path = _declaring_dictionary(tmp_path, "hostile_argv__.rar", 0, _RAR5_DICT_4GIB)
    if not unrar_found:

        def missing() -> str:
            raise PackageNotInstalledError("no RARLAB unrar in this test")

        monkeypatch.setattr(rar_reader, "find_rarlab_unrar", missing)
    with open_archive(path, config=_config("auto")) as archive:
        if unrar_found:
            assert archive.read("canary.txt") == expected
        else:
            with pytest.raises(ResourceLimitError, match="unar needs"):
                archive.read("canary.txt")


@requires_binary("unrar")
def test_rar3_dictionary_counts_the_same_way(no_spawn: None) -> None:
    """RAR3's flag-byte dictionary (1 MiB here) is capped at the bytes decoded.

    ``file1.txt`` is 13 bytes into the solid stream, ``subdir/file2.txt`` ends at 29.
    """
    path = _fixture("basic_solid__rar4.rar")
    with (
        open_archive(path, config=_config("unrar", 16)) as archive,
        pytest.raises(ResourceLimitError, match="max_decoder_memory=16") as excinfo,
    ):
        archive.read("subdir/file2.txt")
    # The count is 29 bytes. Every member declares 1 MiB, the one read included, so
    # the message points at its own header, not at the first member to declare it.
    assert (
        "is 29 bytes, counted from the 1048576-byte dictionary its own header "
        "declares, capped at the unpacked bytes the read decodes"
    ) in str(excinfo.value)


@pytest.mark.parametrize(
    "program",
    [
        pytest.param("unrar", marks=requires_binary("unrar")),
        pytest.param("unar", marks=requires_binary("unar")),
    ],
)
@pytest.mark.parametrize("fixture", ["hostile_argv__.rar", "seek_respawn_solid__.rar"])
def test_honest_dictionaries_read_under_the_default_limit(
    program: str, fixture: str
) -> None:
    config = _config(program)
    with open_archive(_fixture(fixture), config=config) as archive:
        for member in archive.members():
            if member.is_file:
                archive.read(member)
    assert _stream_all(_fixture(fixture), config)


@pytest.mark.parametrize(
    "link", [{"is_hardlink_or_copy": True}, {"is_directory": True}], ids=str
)
def test_an_entry_with_no_data_adds_nothing_to_the_dictionary_count(
    link: dict[str, bool],
) -> None:
    """A hardlink, copy or directory declares a size, but nothing decodes it.

    ``prefix.bin`` is turned into such an entry declaring 4 GiB and 3 GiB. Neither
    program's count for it or for ``tail.txt`` behind it may include those numbers.
    """
    with _fixture("seek_respawn_solid__.rar").open("rb") as f:
        archive = parse_rar_archive(f)
    first = archive.members[0]
    archive.members[0] = dataclasses.replace(
        first, dictionary_size=4 * 2**30, file_size=_3_GIB, **link
    )
    unrar = rar_reader._unrar_dictionary_costs(archive)
    assert unrar[0].count == 0
    assert unrar[1].count <= archive.members[1].file_size
    unar = unar_dictionary_costs(archive)
    assert unar == [(0, -1), (archive.members[1].dictionary_size, 1)]


def _set_main_solid(blocks: list[dict[str, Any]], solid: bool) -> None:
    """Set or clear the MAIN header's solid flag (archive flags bit 2)."""
    main = next(block for block in blocks if block["type"] == 1)
    flags, rest = _read_vint(main["body"], 0)
    flags = flags | 4 if solid else flags & ~4
    main["body"] = _vint(flags) + main["body"][rest:]


@pytest.mark.parametrize("member_solid", [True, False], ids=["member", "no_member"])
@pytest.mark.parametrize("main_solid", [True, False], ids=["main", "no_main"])
def test_unrar_solid_walk_follows_the_main_solid_flag(
    main_solid: bool, member_solid: bool
) -> None:
    """unrar decodes the members ahead of a stored one when the MAIN flag says solid.

    Measured (rar.md section 7): with the MAIN flag set, reading the stored member
    took 314 MiB behind a 1 GiB declaration whatever its own flag said; with it
    clear, unrar decoded nothing ahead, whatever the member's flag said.
    """
    blocks = _rar5_parse(_fixture("seek_respawn_solid__.rar").read_bytes())
    prefix, tail = _rar5_file_blocks(blocks)
    _declare_dictionary(prefix, _RAR5_DICT_4GIB, unpacked=_3_GIB)
    tail["cinfo"] &= ~(7 << 7)  # stored
    tail["cinfo"] = tail["cinfo"] | 0x40 if member_solid else tail["cinfo"] & ~0x40
    _set_main_solid(blocks, main_solid)
    archive = parse_rar_archive(io.BytesIO(_rar5_build(blocks)))
    assert (archive.is_solid, archive.members[1].file_solid) == (
        main_solid,
        member_solid,
    )
    count = rar_reader._unrar_dictionary_costs(archive)[1].count
    assert count == (min(4 * 2**30, _3_GIB) if main_solid else 0)


# --- a directory entry that declares data ---------------------------------------------


def _rar_with_directory_data(
    tmp_path: Path, *, stored: bool, declared_empty: bool = False
) -> Path:
    """The fixture's second member rewritten as a directory (``FHFL_DIRECTORY``) that
    keeps its data. ``rar`` never writes one, so the header is edited in the test.
    ``declared_empty`` sets the unpacked size to 0 over the same body."""
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    files = _rar5_file_blocks(blocks)
    files[1]["file_flags"] |= 1  # FHFL_DIRECTORY
    if stored:
        files[1]["data"] = b"stored dir data"
        files[1]["unpacked"] = len(files[1]["data"])
        files[1]["crc"] = struct.pack("<I", zlib.crc32(files[1]["data"]))
        files[1]["cinfo"] = 0  # method 0 (stored), version 0
    if declared_empty:
        files[1]["unpacked"] = 0
    path = tmp_path / ("dir_stored.rar" if stored else "dir_compressed.rar")
    path.write_bytes(_rar5_build(blocks))
    return path


@requires_binary("unrar")
@pytest.mark.parametrize("stored", [True, False], ids=["stored", "compressed"])
def test_directory_data_is_reported_and_the_directory_created(
    tmp_path: Path, stored: bool
) -> None:
    """unrar creates the directory and skips its data silently; archivey does the same
    on extraction and reports ``MEMBER_DIRECTORY_DATA_IGNORED`` at listing."""
    payloads = _hostile_argv_payloads()
    path = _rar_with_directory_data(tmp_path, stored=stored)
    with open_archive(path, config=_UNRAR_ONLY) as archive:
        members = archive.members()
        assert [m.type for m in members] == [
            MemberType.FILE,
            MemberType.DIRECTORY,
            MemberType.FILE,
        ]
        assert members[1].name == "-inul/"
        assert members[1].size == (15 if stored else len(payloads["-inul"]))
        diags = [
            d
            for d in archive.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED
        ]
        assert len(diags) == 1
        assert diags[0].context is not None
        context = diags[0].context.to_dict()
        assert context["member_name"] == "-inul/"
        assert context["member_id"] == 1
        assert context["size"] == members[1].size
        assert context["compressed_size"] == members[1].compressed_size
        archive.extract_all(tmp_path / "out")
    assert (tmp_path / "out" / "-inul").is_dir()
    assert not any((tmp_path / "out" / "-inul").iterdir())
    assert (tmp_path / "out" / "@atfile").read_bytes() == payloads["@atfile"]


@requires_binary("unrar")
def test_declared_empty_directory_with_a_body_is_reported(tmp_path: Path) -> None:
    """A directory whose unpacked size is 0 over a 15-byte stored body is reported
    with both sizes; ``open()`` has nothing to return for it and says so."""
    path = _rar_with_directory_data(tmp_path, stored=True, declared_empty=True)
    with open_archive(path, config=_UNRAR_ONLY) as archive:
        member = archive.get("-inul/")
        assert member.type is MemberType.DIRECTORY
        assert (member.size, member.compressed_size) == (0, 15)
        [diag] = [
            d
            for d in archive.diagnostics.retained
            if d.code is DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED
        ]
        assert diag.context is not None
        assert diag.context.to_dict()["size"] == 0
        assert diag.context.to_dict()["compressed_size"] == 15
        assert "stores a 15-byte body" in diag.message
        with pytest.raises(ArchiveyUsageError, match="declares no data"):
            archive.read("-inul/")


@requires_binary("unrar")
def test_encrypted_stored_directory_data_is_refused_as_unsupported(
    tmp_path: Path,
) -> None:
    """An encrypted stored body under a directory flag is not sliceable by archivey
    and unrar emits nothing for a directory, so ``open()`` refuses it as unsupported
    instead of handing it to unrar and reporting whatever comes back.

    The committed ``encryption_stored__.rar`` (``-m0 -ppassword``) supplies the
    encrypted stored body; only the directory flag is set on its header."""
    blocks = _rar5_parse(_fixture("encryption_stored__.rar").read_bytes())
    [entry] = _rar5_file_blocks(blocks)
    assert entry["cinfo"] == 0 and entry["data"]  # stored, with a body
    entry["file_flags"] |= 1  # FHFL_DIRECTORY
    path = tmp_path / "enc_dir.rar"
    path.write_bytes(_rar5_build(blocks))
    with open_archive(path, password="password", config=_UNRAR_ONLY) as archive:
        [member] = archive.members()
        assert member.type is MemberType.DIRECTORY
        assert member.size == 14
        assert member.is_encrypted
        codes = [d.code for d in archive.diagnostics.retained]
        assert DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED in codes
        with pytest.raises(UnsupportedFeatureError, match="unencrypted"):
            archive.read(member)


@requires_binary("unrar")
def test_stored_directory_data_reads_and_compressed_is_refused(tmp_path: Path) -> None:
    """Stored directory data is sliced by archivey itself, so ``read()`` returns it.
    unrar emits nothing for a directory entry, so compressed directory data cannot be
    decoded and ``read()`` says why instead of returning nothing."""
    payloads = _hostile_argv_payloads()
    with open_archive(
        _rar_with_directory_data(tmp_path, stored=True), config=_UNRAR_ONLY
    ) as archive:
        assert archive.read("-inul/") == b"stored dir data"
        assert archive.read("@atfile") == payloads["@atfile"]
    with open_archive(
        _rar_with_directory_data(tmp_path, stored=False), config=_UNRAR_ONLY
    ) as archive:
        with pytest.raises(UnsupportedFeatureError, match="cannot deliver"):
            archive.read("-inul/")
        assert archive.read("@atfile") == payloads["@atfile"]
