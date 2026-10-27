"""Regression tests for the second audit's RAR findings (R15 onwards).

Each test states the promised behaviour that the finding named in its section heading
broke.

Most archives are derived from committed fixtures by rewriting headers with the
helpers in ``tests/test_audit_rar_iso_dir.py``, so only ``unrar`` is needed at
runtime. The few that need a real writer skip without ``rar``.
"""

from __future__ import annotations

import copy
import os
import shutil
import signal
import struct
import subprocess
import sys
import textwrap
import zlib
from pathlib import Path
from typing import Any

import pytest

from archivey import (
    ArchiveyConfig,
    ListingLimits,
    MemberType,
    open_archive,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    CorruptionError,
    EncryptionError,
    LinkTargetNotFoundError,
    ResourceLimitError,
    ResourceUnavailableError,
    UnsupportedFeatureError,
)
from tests.conftest import has_binary, requires_binary
from tests.extract_util import open_and_extract
from tests.test_audit_rar_iso_dir import (
    _fixture,
    _hostile_argv_payloads,
    _rar3_build,
    _rar3_parse,
    _rar5_build,
    _rar5_file_blocks,
    _rar5_parse,
)

_UNRAR_ONLY = ArchiveyConfig(rar_decompressor="unrar")


# --- R15: a stored member is sliced by its unpacked size, not its packed size ---


def _stored_member_declaring_more_than_it_packs(tmp_path: Path) -> tuple[Path, bytes]:
    """``basic_nonsolid__.rar`` with ``file1.txt`` (stored, 13 bytes) claiming 40.

    The CRC is dropped (RAR5 makes it optional), so no digest can catch the
    overrun. The packed span is still the real 13 bytes.
    """
    blocks = _rar5_parse(_fixture("basic_nonsolid__.rar").read_bytes())
    first = _rar5_file_blocks(blocks)[0]
    assert first["name"] == b"file1.txt"
    assert first["cinfo"] == 0  # stored
    original = first["data"]
    assert first["unpacked"] == len(original) == 13
    first["unpacked"] = 40
    first["crc"] = None
    path = tmp_path / "overlong_stored.rar"
    path.write_bytes(_rar5_build(blocks))
    return path, original


def test_stored_member_never_reads_past_its_packed_span(tmp_path: Path) -> None:
    """``unrar p`` emits the 13 packed bytes; archivey returned 40.

    The extra 27 bytes are the CRC, size and type fields of the next FILE header,
    handed back as member content with no diagnostic. Refusing is fine; returning
    bytes from outside the member's packed span is not.
    """
    path, original = _stored_member_declaring_more_than_it_packs(tmp_path)
    # A stored nonsolid member is sliced natively: no unrar or unar is involved.
    with open_archive(path) as archive:
        member = archive.members()[0]
        assert member.name == "file1.txt"
        try:
            data = archive.read(member)
        except ArchiveyError:
            return
    assert data == original


# --- R16: a RAR5 file-copy redirect is a FILE, not a hard link -----------------


def _rar_with_copies(tmp_path: Path, *flags: str) -> tuple[Path, bytes]:
    """``r1.bin``, ``other.txt``, ``d/r2.bin``: ``rar -oi`` stores the second copy of
    the payload as a file reference to ``r1.bin`` (redirect type 5), with no data.

    The payload is text, not random bytes: ``unar`` 1.10 fails to decode some solid
    RAR5 archives of near-incompressible data (with or without a copy in them), which
    would make the ``unar`` cases flaky for a reason unrelated to copies."""
    src = tmp_path / "src"
    (src / "d").mkdir(parents=True)
    payload = b"".join(b"line %05d of the copied file\n" % i for i in range(200))
    (src / "r1.bin").write_bytes(payload)
    (src / "other.txt").write_bytes(b"other")
    (src / "d" / "r2.bin").write_bytes(payload)
    archive = tmp_path / "copies.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-oi:1000", *flags, str(archive)]
        + ["r1.bin", "other.txt", "d/r2.bin"],
        cwd=src,
        check=True,
        timeout=60,
    )
    return archive, payload


@requires_binary("rar")
def test_file_copy_redirect_extracts_as_an_independent_file(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    payload = os.urandom(5000)
    (src / "r1.bin").write_bytes(payload)
    (src / "r2.bin").write_bytes(payload)
    archive = tmp_path / "copies.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-ep1", "-oi:1000", str(archive), "r1.bin", "r2.bin"],
        cwd=src,
        check=True,
        timeout=60,
    )
    dest = tmp_path / "out"
    open_and_extract(archive, dest)
    first, second = dest / "r1.bin", dest / "r2.bin"
    assert first.read_bytes() == second.read_bytes() == payload
    # A "file reference" is a copy: writing to one must not change the other.
    assert os.stat(first).st_ino != os.stat(second).st_ino


_COPY_CASES = [
    pytest.param("unrar", (), id="unrar-nonsolid"),
    pytest.param("unrar", ("-s",), id="unrar-solid"),
    pytest.param("unar", (), id="unar-nonsolid"),
    pytest.param("unar", ("-s",), id="unar-solid"),
]


def _copy_reader_config(decompressor: str) -> ArchiveyConfig:
    if shutil.which("rar") is None or not has_binary(decompressor):
        pytest.skip(f"needs rar and {decompressor}")
    if decompressor == "unar":
        return ArchiveyConfig(rar_decompressor="unar")
    return _UNRAR_ONLY


@pytest.mark.parametrize(("decompressor", "flags"), _COPY_CASES)
def test_file_copy_lists_as_a_file_that_names_its_source(
    tmp_path: Path, decompressor: str, flags: tuple[str, ...]
) -> None:
    config = _copy_reader_config(decompressor)
    archive, payload = _rar_with_copies(tmp_path, *flags)
    with open_archive(archive, config=config) as reader:
        source = reader.get("r1.bin")
        copy_member = reader.get("d/r2.bin")
        assert copy_member.type is MemberType.FILE
        assert copy_member.is_file and not copy_member.is_link
        # The two markers that say it is a copy, and of what.
        assert copy_member.extra["is_file_copy"] is True
        assert copy_member.link_target == "r1.bin"
        assert copy_member.link_target_member is source
        assert copy_member.size == source.size == len(payload)
        # Its own CRC field covers no bytes; the source's digest checks the read.
        assert copy_member.hashes == {}
        assert "is_file_copy" not in source.extra
        assert reader.read(copy_member) == payload
        with reader.open("d/r2.bin") as stream:
            assert stream.read() == payload


@pytest.mark.parametrize(("decompressor", "flags"), _COPY_CASES)
def test_file_copy_yields_its_bytes_in_stream_members_order(
    tmp_path: Path, decompressor: str, flags: tuple[str, ...]
) -> None:
    config = _copy_reader_config(decompressor)
    archive, payload = _rar_with_copies(tmp_path, *flags)
    seen: list[tuple[str, bytes | None]] = []
    with open_archive(archive, config=config) as reader:
        for member, stream in reader.stream_members():
            seen.append((member.name, None if stream is None else stream.read()))
    # The copy is not in the solid pipe; reading it does not shift its neighbours.
    assert dict(seen) == {"r1.bin": payload, "other.txt": b"other", "d/r2.bin": payload}
    names = [name for name, _ in seen]
    assert names.index("r1.bin") < names.index("d/r2.bin")


@pytest.mark.parametrize(("decompressor", "flags"), _COPY_CASES)
def test_file_copy_extracts_as_an_independent_file_on_every_path(
    tmp_path: Path, decompressor: str, flags: tuple[str, ...]
) -> None:
    config = _copy_reader_config(decompressor)
    archive, payload = _rar_with_copies(tmp_path, *flags)
    dest = tmp_path / "out"
    open_and_extract(archive, dest, config=config)
    first, second = dest / "r1.bin", dest / "d" / "r2.bin"
    assert first.read_bytes() == second.read_bytes() == payload
    assert (dest / "other.txt").read_bytes() == b"other"
    assert os.stat(first).st_ino != os.stat(second).st_ino


@requires_binary("rar")
@requires_binary("unrar")
def test_file_copy_without_a_matching_source_is_a_typed_error(tmp_path: Path) -> None:
    """The source must be an earlier FILE of the same size; a copy whose target names
    no member lists, and raises ``LinkTargetNotFoundError`` when read, and a copy
    declaring a size its source does not have raises ``CorruptionError``."""
    archive, _ = _rar_with_copies(tmp_path)
    blocks = _rar5_parse(archive.read_bytes())
    copy_block = _rar5_file_blocks(blocks)[-1]
    assert copy_block["name"] == b"d/r2.bin"

    dangling = copy.deepcopy(blocks)
    dangling_copy = _rar5_file_blocks(dangling)[-1]
    extra = dangling_copy["extra"]
    at = extra.rindex(b"r1.bin")
    dangling_copy["extra"] = extra[:at] + b"r9.bin" + extra[at + 6 :]
    path = tmp_path / "dangling.rar"
    path.write_bytes(_rar5_build(dangling))
    with open_archive(path, config=_UNRAR_ONLY) as reader:
        member = reader.get("d/r2.bin")
        assert member.type is MemberType.FILE
        assert member.link_target == "r9.bin"
        assert member.link_target_member is None
        with pytest.raises(LinkTargetNotFoundError):
            reader.read(member)

    resized = copy.deepcopy(blocks)
    _rar5_file_blocks(resized)[-1]["unpacked"] = 4000
    path = tmp_path / "resized.rar"
    path.write_bytes(_rar5_build(resized))
    with (
        open_archive(path, config=_UNRAR_ONLY) as reader,
        pytest.raises(CorruptionError),
    ):
        reader.read("d/r2.bin")


@requires_binary("rar")
@requires_binary("unrar")
def test_rar5_hard_link_stays_a_hardlink(tmp_path: Path) -> None:
    """Control: a real hard link (``rar -oh``) is still ``HARDLINK`` and extracts as one."""
    src = tmp_path / "src"
    src.mkdir()
    payload = os.urandom(3000)
    (src / "a.bin").write_bytes(payload)
    os.link(src / "a.bin", src / "b.bin")
    archive = tmp_path / "hard.rar"
    subprocess.run(
        ["rar", "a", "-idq", "-oh", str(archive), "a.bin", "b.bin"],
        cwd=src,
        check=True,
        timeout=60,
    )
    with open_archive(archive, config=_UNRAR_ONLY) as reader:
        link = reader.get("b.bin")
        assert link.type is MemberType.HARDLINK
        assert "is_file_copy" not in link.extra
        assert link.link_target == "a.bin"
        assert reader.read(link) == payload
    dest = tmp_path / "out"
    open_and_extract(archive, dest)
    assert os.stat(dest / "a.bin").st_ino == os.stat(dest / "b.bin").st_ino


# --- R17/R18: names made only of dots and slashes ------------------------------


def _dot_named_archive(tmp_path: Path) -> tuple[Path, dict[str, bytes]]:
    """Four compressed members: ``canary.txt``, ``./``, ``...``, ``...``.

    ``./`` and the first ``...`` both carry ``-inul``'s 1216 bytes; the second
    ``...`` carries ``@atfile``'s 1216 bytes. The first ``...`` has no CRC.
    ``unrar p -n./...`` emits exactly the two ``...`` members; archivey's model
    of that selection also counts ``./``.
    """
    payloads = _hostile_argv_payloads()
    assert len(payloads["-inul"]) == len(payloads["@atfile"])
    blocks = _rar5_parse(_fixture("hostile_argv__.rar").read_bytes())
    files = _rar5_file_blocks(blocks)
    extra = copy.deepcopy(files[1])
    extra["name"] = b"./"
    blocks.insert(blocks.index(files[1]), extra)
    files[1]["name"] = b"..."
    files[1]["crc"] = None
    files[2]["name"] = b"..."
    path = tmp_path / "dots.rar"
    path.write_bytes(_rar5_build(blocks))
    return path, payloads


@requires_binary("unrar")
def test_dot_named_member_never_reads_a_siblings_bytes(tmp_path: Path) -> None:
    path, payloads = _dot_named_archive(tmp_path)
    with open_archive(path, config=_UNRAR_ONLY) as archive:
        members = archive.members()
        target = members[2]
        assert target.name == "..."
        assert target.hashes == {}
        try:
            data = archive.read(target)
        except ArchiveyError:
            return  # refusing is acceptable; the sibling's bytes are not
    assert data != payloads["@atfile"]
    assert data == payloads["-inul"]


@requires_binary("unrar")
def test_member_unrar_cannot_address_is_refused_not_reported_corrupt(
    tmp_path: Path,
) -> None:
    """``rar.md`` §5: such a name raises ``UnsupportedFeatureError`` on the unrar path.

    ``unrar`` emits nothing for it. With a CRC the empty pipe surfaces as
    ``TruncatedError``; without one, exit 10 ("no files matched") maps to
    ``CorruptionError``. Both tell the caller the archive is damaged, and ``unar``
    (which addresses entries by index) reads the member fine.
    """
    path, _payloads = _dot_named_archive(tmp_path)
    with open_archive(path, config=_UNRAR_ONLY) as archive:
        member = archive.members()[1]
        with pytest.raises(UnsupportedFeatureError):
            archive.read(member)


# --- R19: a wrong password on a solid RAR3/4 pass reads as truncation ---------


def _solid_encrypted_rar4(tmp_path: Path) -> Path:
    """``encryption__rar4.rar`` (password ``password``) with the MAIN solid flag set.

    Neither FILE header carries the per-file solid flag, so ``unrar`` decodes
    both members exactly as before; only the archive-level flag changes, which is
    what sends archivey's ``stream_members()`` and ``extract_all()`` through the
    one-``unrar``-for-the-archive solid pass.
    """
    blocks = _rar3_parse(_fixture("encryption__rar4.rar").read_bytes())
    main = blocks[0]
    assert main["type"] == 0x73
    flags = struct.unpack_from("<H", main["header"], 3)[0]
    struct.pack_into("<H", main["header"], 3, flags | 0x0008)
    path = tmp_path / "solid_encrypted_rar4.rar"
    path.write_bytes(_rar3_build(blocks))
    return path


@requires_binary("unrar")
@pytest.mark.parametrize("via", ["stream_members", "extract"])
def test_solid_rar4_wrong_password_is_an_encryption_error(
    tmp_path: Path, via: str
) -> None:
    path = _solid_encrypted_rar4(tmp_path)
    # Control: the crafted archive is valid and reads through the solid pass.
    with open_archive(path, password="password", config=_UNRAR_ONLY) as archive:
        assert archive.info.is_solid
        sizes = [len(s.read()) for _, s in archive.stream_members() if s is not None]
    assert sizes and all(sizes)
    # The random-access path already says "wrong password":
    with (
        open_archive(path, password="wrong", config=_UNRAR_ONLY) as archive,
        pytest.raises(EncryptionError),
    ):
        archive.read(archive.members()[0])
    with pytest.raises(EncryptionError):
        if via == "stream_members":
            with open_archive(path, password="wrong", config=_UNRAR_ONLY) as archive:
                for _, stream in archive.stream_members():
                    if stream is not None:
                        stream.read()
        else:
            open_and_extract(
                path, tmp_path / "out", password="wrong", config=_UNRAR_ONLY
            )


# --- R20: a str password holding a lone surrogate escapes as UnicodeEncodeError --


def test_surrogate_escaped_password_raises_no_bare_unicode_error() -> None:
    """``sys.argv`` decodes a Latin-1 ``--password é`` to ``'\\udce9'``.

    Either the password is encoded back with ``surrogateescape`` (the bytes the
    user typed) and judged like any other, or it is refused with a typed error.
    ``archivey list --password $'\\xe9' archive.rar`` must not end in a traceback.
    """
    try:
        with open_archive(
            _fixture("encryption__rar4.rar"), password="\udce9", config=_UNRAR_ONLY
        ) as archive:
            archive.members()
    except (ArchiveyError, ArchiveyUsageError):
        pass


# --- R21: unrar and archivey pick different next volumes -----------------------

_CRC_POLY = 0xEDB88320
_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ _CRC_POLY if _c & 1 else _c >> 1
    _CRC_TABLE.append(_c)
_CRC_TOP = {entry >> 24: index for index, entry in enumerate(_CRC_TABLE)}


def _force_crc32(data: bytes, pos: int, target: int) -> bytes:
    """``data`` with ``data[pos:pos+4]`` rewritten so its CRC32 is ``target``."""
    out = bytearray(data)
    state = zlib.crc32(bytes(out[:pos])) ^ 0xFFFFFFFF
    want = target ^ 0xFFFFFFFF
    for byte in reversed(out[pos + 4 :]):
        index = _CRC_TOP[want >> 24]
        want = ((want ^ _CRC_TABLE[index]) << 8 | (index ^ byte)) & 0xFFFFFFFF
    for _ in range(4):
        index = _CRC_TOP[want >> 24]
        want = ((want ^ _CRC_TABLE[index]) << 8 | index) & 0xFFFFFFFF
    out[pos : pos + 4] = (want ^ state).to_bytes(4, "little")
    assert zlib.crc32(bytes(out)) == target
    return bytes(out)


@requires_binary("unrar")
def test_unrar_reads_the_volumes_archivey_parsed(tmp_path: Path) -> None:
    """``tinyvol_rnn`` is a RAR 2.0 set whose MAIN header says old-style naming.

    Renamed ``x.part1.rar`` / ``x.part2.rar``, archivey's sibling discovery finds
    ``x.part2.rar``. ``unrar`` follows the header flag and looks for
    ``x.part1.r00`` instead: with no such file the read failed as truncated; with
    one, its bytes came back. The decoy's stored data is chosen so the whole-file
    CRC32 archivey checks still matches. Fixed: the set is staged under the
    names unrar expects, so unrar reads exactly the files archivey parsed.
    """
    first = _rar3_parse(_fixture("tinyvol_rnn.rar").read_bytes())
    second = _rar3_parse(_fixture("tinyvol_rnn.r00").read_bytes())
    head_data = first[1]["data"]
    tail = second[1]
    whole_crc = struct.unpack_from("<I", tail["header"], 16)[0]
    original = head_data + tail["data"]
    assert zlib.crc32(original) == whole_crc

    (tmp_path / "x.part1.rar").write_bytes(_fixture("tinyvol_rnn.rar").read_bytes())
    (tmp_path / "x.part2.rar").write_bytes(_fixture("tinyvol_rnn.r00").read_bytes())
    evil = (b"DECOY-VOLUME-ARCHIVEY-NEVER-PARSED\n" * 40)[: len(tail["data"])]
    forged = _force_crc32(head_data + evil, len(original) - 4, whole_crc)
    tail["data"] = forged[len(head_data) :]
    (tmp_path / "x.part1.r00").write_bytes(_rar3_build(second))

    with open_archive(tmp_path / "x.part1.rar", config=_UNRAR_ONLY) as archive:
        member = archive.members()[0]
        try:
            data = archive.read(member)
        except ArchiveyError:
            return  # refusing is acceptable; the decoy's bytes are not
    assert b"DECOY" not in data
    assert data == original


@requires_binary("unrar")
def test_renamed_old_numbering_set_reads_without_a_decoy(tmp_path: Path) -> None:
    """The same renamed set with no ``x.part1.r00``: it reads, not truncated."""
    first = _rar3_parse(_fixture("tinyvol_rnn.rar").read_bytes())
    second = _rar3_parse(_fixture("tinyvol_rnn.r00").read_bytes())
    original = first[1]["data"] + second[1]["data"]
    (tmp_path / "x.part1.rar").write_bytes(_fixture("tinyvol_rnn.rar").read_bytes())
    (tmp_path / "x.part2.rar").write_bytes(_fixture("tinyvol_rnn.r00").read_bytes())

    with open_archive(tmp_path / "x.part1.rar", config=_UNRAR_ONLY) as archive:
        assert archive.read(archive.members()[0]) == original


# --- R22: an unrar/unar killed from outside is reported as a truncated archive --


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")
@pytest.mark.parametrize("signame", ["SIGKILL", "SIGTERM"])
@pytest.mark.parametrize("decompressor", ["unrar", "unar"])
def test_externally_killed_decompressor_is_not_reported_as_truncation(
    decompressor: str, signame: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``child_process``: a child ended from outside says nothing about the data.

    ``seek_respawn_solid__.rar`` holds a 1 MiB member, far more than a pipe buffer,
    so the child is still blocked writing when it is killed after the first read.
    ``unrar`` catches SIGTERM and exits 255 (user break) instead of dying on it.
    """
    if not has_binary(decompressor):
        pytest.skip(f"requires {decompressor}")
    from archivey.internal.backends import rar_unrar
    from archivey.internal.external import unar as unar_module

    procs: list[subprocess.Popen[bytes]] = []
    module = rar_unrar if decompressor == "unrar" else unar_module
    real_spawn = module.spawn_for_stdout

    def recording_spawn(*args: Any, **kwargs: Any) -> Any:
        proc, stdout = real_spawn(*args, **kwargs)
        procs.append(proc)
        return proc, stdout

    monkeypatch.setattr(module, "spawn_for_stdout", recording_spawn)
    config = ArchiveyConfig(rar_decompressor=decompressor)
    with open_archive(_fixture("seek_respawn_solid__.rar"), config=config) as archive:
        member = next(m for m in archive.members() if m.name == "prefix.bin")
        with archive.open(member) as stream:
            assert stream.read(1000)
            (proc,) = procs
            if proc.poll() is not None:
                pytest.skip("the child finished before it could be killed")
            proc.send_signal(getattr(signal, signame))
            with pytest.raises(ArchiveyError) as info:
                while stream.read(1 << 16):
                    pass
    assert not isinstance(info.value, CorruptionError), repr(info.value)
    if signame == "SIGKILL":
        assert isinstance(info.value, ResourceUnavailableError), repr(info.value)


# --- R23: the RAR5 archive comment is read by its unpacked size ----------------


def _comment_declaring(tmp_path: Path, unpacked: int) -> Path:
    """``comment__.rar`` with its stored ``CMT`` service header claiming ``unpacked``.

    The packed span (28 bytes) is unchanged; ``unrar l`` still prints the real
    comment.
    """
    blocks = _rar5_parse(_fixture("comment__.rar").read_bytes())
    cmt = next(block for block in blocks if block["type"] == 3)
    assert cmt["name"] == b"CMT"
    assert cmt["unpacked"] == len(cmt["data"]) == 28
    cmt["unpacked"] = unpacked
    path = tmp_path / "cmt.rar"
    path.write_bytes(_rar5_build(blocks))
    return path


def test_rar5_comment_never_reads_past_its_packed_span(tmp_path: Path) -> None:
    path = _comment_declaring(tmp_path, 40)
    try:
        with open_archive(path) as archive:
            comment = archive.info.comment
    except ArchiveyError:
        return
    assert comment in (None, "This is a\nmulti-line comment")


def test_rar5_comment_that_is_not_utf8_keeps_its_bytes(tmp_path: Path) -> None:
    """A byte that is not valid UTF-8 survives as a lone surrogate, as in a RAR5 name.

    RARLAB ``rar`` never stores one: it maps such a byte to U+FFFE plus a private-use
    character, which is valid UTF-8. A crafted comment gets the name's reading, not
    U+FFFD, which would lose the byte.
    """
    blocks = _rar5_parse(_fixture("comment__.rar").read_bytes())
    cmt = next(block for block in blocks if block["type"] == 3)
    data = b"caf\xe9 \xff ok"
    cmt["data"] = data
    cmt["unpacked"] = len(data)
    if cmt["crc"] is not None:
        cmt["crc"] = struct.pack("<I", zlib.crc32(data))
    path = tmp_path / "cmt.rar"
    path.write_bytes(_rar5_build(blocks))
    # encoding= does not apply: a RAR5 comment is UTF-8 by the format.
    with open_archive(path, encoding="cp1252") as archive:
        assert archive.info.comment == "caf\udce9 \udcff ok"


_OPEN_UNDER_RLIMIT = textwrap.dedent(
    """
    import resource, sys
    try:
        resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
    except (ValueError, OSError):
        pass  # macOS cannot lower RLIMIT_AS; the chunked read allocates little anyway
    from archivey import open_archive
    from archivey.exceptions import ArchiveyError
    try:
        with open_archive(sys.argv[1]) as archive:
            archive.info.comment
    except ArchiveyError as exc:
        print("typed", type(exc).__name__)
    except MemoryError:
        print("MemoryError")
    else:
        print("opened")
    """
)


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_AS is POSIX")
def test_rar5_comment_huge_declared_size_is_not_a_memory_error(
    tmp_path: Path,
) -> None:
    path = _comment_declaring(tmp_path, 1 << 40)
    result = subprocess.run(
        [sys.executable, "-c", _OPEN_UNDER_RLIMIT, str(path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    outcome = result.stdout.strip()
    assert outcome == "opened" or outcome.startswith("typed "), (
        result.stdout + result.stderr
    )


def _rar3_newsub_comment(tmp_path: Path, *, high_packed: int) -> Path:
    """``hostile_argv__rar4.rar`` with a stored RAR 2.9 ``CMT`` sub-block added.

    ``high_packed`` goes in the LARGE-file high 32 bits of the packed size, so
    the header claims ``high_packed << 32`` more bytes than the 13 it carries.
    """
    blocks = _rar3_parse(_fixture("hostile_argv__rar4.rar").read_bytes())
    data = b"hello comment"
    flags = 0x8000 | (0x0100 if high_packed else 0)
    name = b"CMT"
    body = struct.pack(
        "<IIBIIBBHI", len(data), len(data), 3, zlib.crc32(data), 0, 29, 0x30, 3, 0
    )
    if high_packed:
        body += struct.pack("<II", high_packed, 0)
    body += name
    header = bytearray(struct.pack("<HBHH", 0, 0x7A, flags, 7 + len(body)) + body)
    blocks.insert(1, {"type": 0x7A, "header": header, "data": data})
    path = tmp_path / "cmt3.rar"
    path.write_bytes(_rar3_build(blocks))
    return path


@pytest.mark.skipif(sys.platform == "win32", reason="RLIMIT_AS is POSIX")
def test_rar3_comment_huge_packed_size_is_not_a_memory_error(tmp_path: Path) -> None:
    control = _rar3_newsub_comment(tmp_path, high_packed=0)
    with open_archive(control) as archive:
        assert archive.info.comment == "hello comment"
    path = _rar3_newsub_comment(tmp_path, high_packed=256)
    result = subprocess.run(
        [sys.executable, "-c", _OPEN_UNDER_RLIMIT, str(path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    outcome = result.stdout.strip()
    assert outcome == "opened" or outcome.startswith("typed "), (
        result.stdout + result.stderr
    )


def test_stored_comment_over_the_metadata_budget_is_refused() -> None:
    """Sibling of R23: an honest stored comment is weighed like a compressed one."""
    config = ArchiveyConfig(listing_limits=ListingLimits(max_metadata_bytes=16))
    with (
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
        open_archive(_fixture("comment__.rar"), config=config),
    ):
        pass
