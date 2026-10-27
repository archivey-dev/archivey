"""A RAR member compressed with a version ``unrar`` does not know is unsupported.

``unrar`` 7.00 decodes RAR5 compression-info versions 0 and 1 and RAR 1.5-4
``UNP_VER`` 13 to 29. For anything else it prints "Unknown method" and "You may need
a newer version of RAR" and writes nothing, which archivey used to report as a
truncation ("ended after 0 of N bytes"). The data is not short; it is newer than the
decoder. Same ruling as lzip version 0.
"""

from __future__ import annotations

import io
import subprocess
import zlib
from collections.abc import Callable
from functools import partial
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, open_archive
from archivey.config import RarDecompressor
from archivey.exceptions import (
    PackageNotInstalledError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends.rar_parser import (
    RarArchive,
    load_vint,
    parse_rar_archive,
)
from archivey.internal.backends.rar_unar import (
    UnarRarPolicy,
    solid_after_unknown_compression,
)
from archivey.reader import ArchiveReader
from archivey.types import ArchiveMember
from tests.atheris_fuzz.crc_fixup import fixup_rar_header_crcs
from tests.conftest import binary_refusal, requires_binary, requires_unrar_cli

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"


def _set_rar5_version(data: bytes, member_index: int, version: int) -> bytes:
    """Set the compression-info version bits of the ``member_index``-th FILE header."""
    buf = bytearray(data)
    pos = 8
    seen = 0
    while pos < len(buf):
        size, body = load_vint(bytes(buf), pos + 4)
        end = body + size
        block_type, p = load_vint(bytes(buf), body)
        flags, p = load_vint(bytes(buf), p)
        if flags & 0x0001:
            _, p = load_vint(bytes(buf), p)
        data_size = 0
        if flags & 0x0002:
            data_size, p = load_vint(bytes(buf), p)
        if block_type == 2:
            if seen == member_index:
                file_flags, p = load_vint(bytes(buf), p)
                _, p = load_vint(bytes(buf), p)  # unpacked size
                _, p = load_vint(bytes(buf), p)  # attributes
                p += 4 if file_flags & 0x0002 else 0  # mtime
                p += 4 if file_flags & 0x0004 else 0  # CRC32
                buf[p] = (buf[p] & ~0x3F) | version
                return fixup_rar_header_crcs(bytes(buf), broken=False)
            seen += 1
        pos = end + data_size
    raise AssertionError(f"no FILE header {member_index}")


def _set_rar4_unp_ver(
    data: bytes, version: int, member_index: int | None = None
) -> bytes:
    """Set ``UNP_VER`` on every FILE header of a RAR 1.5-4 archive, or only on the
    ``member_index``-th one."""
    buf = bytearray(data)
    pos = 7
    seen = 0
    while pos + 7 <= len(buf):
        block_type = buf[pos + 2]
        flags = int.from_bytes(buf[pos + 3 : pos + 5], "little")
        size = int.from_bytes(buf[pos + 5 : pos + 7], "little")
        add = 0
        if block_type == 0x74:
            add = int.from_bytes(buf[pos + 7 : pos + 11], "little")
            if member_index is None or seen == member_index:
                buf[pos + 24] = version
            seen += 1
        elif flags & 0x8000:
            add = int.from_bytes(buf[pos + 7 : pos + 11], "little")
        if block_type == 0x7B:
            break
        pos += size + add
    return fixup_rar_header_crcs(bytes(buf), broken=False)


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _config(decompressor: str) -> ArchiveyConfig:
    return ArchiveyConfig(rar_decompressor=RarDecompressor(decompressor))


@pytest.mark.parametrize("decompressor", ["unrar", "unar"])
def test_an_unknown_rar5_version_is_unsupported_not_truncated(
    tmp_path: Path, decompressor: str
) -> None:
    """Refused before any process runs, so it needs neither program installed. The
    message is the same whichever decompressor is selected: switching does not help,
    so it must not read as a refusal of one program."""
    data = (_FIXTURES / "hostile_argv__.rar").read_bytes()
    path = _write(tmp_path, "v2.rar", _set_rar5_version(data, 1, 2))
    with open_archive(path, config=_config(decompressor)) as archive:
        member = archive.members()[1]
        with (
            pytest.raises(
                UnsupportedFeatureError, match="compression version 2"
            ) as caught,
            archive.open(member) as stream,
        ):
            stream.read()
    message = str(caught.value)
    assert "neither RAR decompressor" in message, message
    assert "switching decompressors does not help" in message, message
    assert "rar_decompressor" not in message, message


def test_the_unar_solid_pass_refusal_names_no_one_program() -> None:
    """The ``unar`` solid pass refuses such a member from its own policy, which an
    ``open`` never reaches (the reader refuses first). Its words are the reader's:
    the bounds were measured on ``unrar`` only, and switching does not help."""
    data = (_FIXTURES / "hostile_argv__.rar").read_bytes()
    archive = parse_rar_archive(
        io.BytesIO(_set_rar5_version(data, 1, 2)), password=None
    )
    target = archive.members[1]
    refusal = UnarRarPolicy(archive).member_refusal(target)
    assert refusal is not None
    assert "compression version 2" in refusal, refusal
    assert "neither RAR decompressor" in refusal, refusal
    assert "switching decompressors does not help" in refusal, refusal


@pytest.mark.parametrize("decompressor", ["unrar", "unar"])
def test_the_other_members_still_read(tmp_path: Path, decompressor: str) -> None:
    refusal = binary_refusal(decompressor)
    if refusal is not None:
        pytest.skip(refusal)
    data = (_FIXTURES / "hostile_argv__.rar").read_bytes()
    path = _write(tmp_path, "v2.rar", _set_rar5_version(data, 1, 2))
    outcomes: dict[str, object] = {}
    with open_archive(path, config=_config(decompressor)) as archive:
        for member, stream in archive.stream_members():
            if stream is None:
                continue
            try:
                outcomes[member.name] = len(stream.read())
            except UnsupportedFeatureError:
                outcomes[member.name] = UnsupportedFeatureError
    assert outcomes == {
        "canary.txt": 1408,
        "-inul": UnsupportedFeatureError,
        "@atfile": 1216,
    }


def test_rar5_version_1_is_known() -> None:
    """RAR 7.0's algorithm version; ``unrar`` 7.00 decodes it."""
    data = (_FIXTURES / "hostile_argv__.rar").read_bytes()
    archive = parse_rar_archive(io.BytesIO(_set_rar5_version(data, 1, 1)))
    assert archive.members[1].unknown_compression_version() is None
    archive = parse_rar_archive(io.BytesIO(_set_rar5_version(data, 1, 2)))
    assert archive.members[1].unknown_compression_version() is not None


def test_a_stored_member_reads_whatever_version_it_declares(tmp_path: Path) -> None:
    """``unrar`` copies stored data without looking at the version, and so does
    archivey's direct read."""
    data = (_FIXTURES / "stored_m0.rar").read_bytes()
    path = _write(tmp_path, "stored_v7.rar", _set_rar5_version(data, 0, 7))
    with open_archive(path) as archive:
        (member,) = archive.members()
        with archive.open(member) as stream:
            assert len(stream.read()) == member.size


@pytest.mark.parametrize("version", [10, 30, 36, 99])
def test_an_unknown_rar4_version_is_unsupported(tmp_path: Path, version: int) -> None:
    """``unrar`` 7.00 says "Unknown method" below 13 and above 29, measured on this
    fixture; 36 included."""
    data = (_FIXTURES / "hostile_argv__rar4.rar").read_bytes()
    path = _write(tmp_path, f"v{version}.rar", _set_rar4_unp_ver(data, version))
    with open_archive(path) as archive:
        member = archive.members()[0]
        with (
            pytest.raises(UnsupportedFeatureError, match=f"version {version}"),
            archive.open(member) as stream,
        ):
            stream.read()


def test_the_solid_unrar_pass_refuses_the_member_and_keeps_the_ones_before(
    tmp_path: Path,
) -> None:
    """``unrar p`` writes nothing for the member, so it takes no room in the pipe.
    Members before it still read. One after it in the same solid stream cannot be
    decoded either (``unrar`` stops there), and is unsupported for the same reason:
    it used to fail as ``TruncatedError``, which reported the archive as damaged."""
    refusal = binary_refusal("unrar")
    if refusal is not None:
        pytest.skip(refusal)
    data = (_FIXTURES / "basic_solid__.rar").read_bytes()
    path = _write(tmp_path, "solid_v2.rar", _set_rar5_version(data, 2, 2))
    outcomes: dict[str, object] = {}
    with open_archive(path, config=_config("unrar")) as archive:
        for member, stream in archive.stream_members():
            if stream is None:
                continue
            try:
                outcomes[member.name] = len(stream.read())
            except UnsupportedFeatureError:
                outcomes[member.name] = UnsupportedFeatureError
            except TruncatedError:
                outcomes[member.name] = TruncatedError
    assert outcomes == {
        "empty_file.txt": 0,
        "file1.txt": 13,
        "subdir/file2.txt": UnsupportedFeatureError,
        "implicit_subdir/file3.txt": UnsupportedFeatureError,
    }


@requires_unrar_cli()
@pytest.mark.parametrize(
    ("fixture", "mutate"),
    [
        ("hostile_argv__.rar", lambda d: _set_rar5_version(d, 1, 2)),
        ("hostile_argv__rar4.rar", lambda d: _set_rar4_unp_ver(d, 36)),
    ],
    ids=["rar5-v2", "rar4-v36"],
)
def test_unrar_reports_an_unknown_method(
    tmp_path: Path, fixture: str, mutate: Callable[[bytes], bytes]
) -> None:
    """The oracle: ``unrar`` names the same members as unknown, not as damaged."""
    path = _write(tmp_path, "oracle.rar", mutate((_FIXTURES / fixture).read_bytes()))
    result = subprocess.run(
        ["unrar", "t", "-p-", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    assert "Unknown method" in output, output


@pytest.mark.parametrize(
    ("fixture", "mutate", "blocker", "blocked"),
    [
        pytest.param(
            "basic_solid__.rar",
            lambda d: _set_rar5_version(d, 2, 2),
            "subdir/file2.txt",
            "implicit_subdir/file3.txt",
            id="rar5",
        ),
        pytest.param(
            "basic_solid__rar4.rar",
            lambda d: _set_rar4_unp_ver(d, 36, member_index=1),
            "file1.txt",
            "subdir/file2.txt",
            id="rar4",
        ),
    ],
)
def test_a_solid_member_after_an_unknown_version_is_unsupported_on_open(
    tmp_path: Path,
    fixture: str,
    mutate: Callable[[bytes], bytes],
    blocker: str,
    blocked: str,
) -> None:
    """Decoding a solid member means decoding the members before it in its stream,
    and ``unrar`` stops at the unknown one. Refused from the header, before any
    process runs, so it needs no program installed. The message names the member
    that is the reason."""
    path = _write(tmp_path, "solid.rar", mutate((_FIXTURES / fixture).read_bytes()))
    with open_archive(path) as archive:
        member = next(m for m in archive.members() if m.name == blocked)
        with (
            pytest.raises(UnsupportedFeatureError) as caught,
            archive.open(member) as stream,
        ):
            stream.read()
    message = str(caught.value)
    assert repr(blocker) in message, message
    assert "in its solid stream" in message, message
    assert "switching decompressors does not help" in message, message


def _solid_groups_first_member_v2(tmp_path: Path) -> Path:
    """``solid_groups__.rar`` (``-s2``) with ``a.txt`` at compression version 2:
    ``b.txt`` shares its solid stream, ``c.txt`` starts the next one."""
    data = (_FIXTURES / "solid_groups__.rar").read_bytes()
    return _write(tmp_path, "groups_v2.rar", _set_rar5_version(data, 0, 2))


def _open_and_read(archive: ArchiveReader, member: ArchiveMember) -> bytes:
    with archive.open(member) as stream:
        return stream.read()


def _read_outcomes(
    path: Path, config: ArchiveyConfig, *, in_pass: bool
) -> tuple[dict[str, object], dict[str, str]]:
    """Each file member's length or error type, and each refusal's message."""
    outcomes: dict[str, object] = {}
    messages: dict[str, str] = {}

    def record(name: str, read: Callable[[], bytes]) -> None:
        try:
            outcomes[name] = len(read())
        except UnsupportedFeatureError as exc:
            outcomes[name] = UnsupportedFeatureError
            messages[name] = str(exc)
        except TruncatedError:
            outcomes[name] = TruncatedError

    with open_archive(path, config=config) as archive:
        if in_pass:
            for member, stream in archive.stream_members():
                if stream is not None and member.is_file:
                    record(member.name, stream.read)
        else:
            for member in archive.members():
                if member.is_file:
                    record(member.name, partial(_open_and_read, archive, member))
    return outcomes, messages


@pytest.mark.parametrize("in_pass", [False, True], ids=["open", "pass"])
def test_unrar_refuses_a_later_solid_group_for_its_include_mask(
    tmp_path: Path, in_pass: bool
) -> None:
    """``c.txt`` starts a new solid group (solid flag clear), but archivey asks
    ``unrar`` for a member through an include mask, and with a mask ``unrar``
    decodes a solid archive from its start, so it stops at ``a.txt`` for every
    member after it (oracle below). Every one of them is unsupported under
    ``unrar``, in random access and in a pass, refused before ``unrar`` runs. The
    message tells the two causes apart: ``b.txt`` needs ``a.txt`` decoded, while
    ``d.txt`` is blocked only by how archivey runs ``unrar``, and ``unar`` reads
    it."""
    outcomes, messages = _read_outcomes(
        _solid_groups_first_member_v2(tmp_path), _config("unrar"), in_pass=in_pass
    )
    assert outcomes == {
        "a.txt": UnsupportedFeatureError,
        "b.txt": UnsupportedFeatureError,
        "c.txt": UnsupportedFeatureError,
        "d.txt": UnsupportedFeatureError,
    }
    same, later = messages["b.txt"], messages["d.txt"]
    assert "'a.txt' in its solid stream" in same, same
    assert "switching decompressors does not help" in same, same
    assert "'a.txt'" in later, later
    assert "is not in that member's solid stream" in later, later
    assert "include mask" in later, later
    assert "rar_decompressor to 'unar'" in later, later
    assert "switching decompressors does not help" not in later, later


@pytest.mark.parametrize("in_pass", [False, True], ids=["open", "pass"])
def test_unar_reads_a_later_solid_group(tmp_path: Path, in_pass: bool) -> None:
    """``unar`` addresses an entry by index and does not decode the stream ahead of
    one that starts a new stream (oracle below), so only ``b.txt``, which shares
    ``a.txt``'s stream, is refused."""
    refusal = binary_refusal("unar")
    if refusal is not None:
        pytest.skip(refusal)
    outcomes, messages = _read_outcomes(
        _solid_groups_first_member_v2(tmp_path), _config("unar"), in_pass=in_pass
    )
    assert outcomes == {
        "a.txt": UnsupportedFeatureError,
        "b.txt": UnsupportedFeatureError,
        "c.txt": 840,
        "d.txt": 840,
    }
    assert "'a.txt' in its solid stream" in messages["b.txt"], messages


def _main_solid_bit_cleared(data: bytes) -> bytes:
    """A RAR5 archive with the main header's solid bit cleared and every member's
    solid flag left as it was."""
    buf = bytearray(data)
    _, body = load_vint(data, 8 + 4)
    block_type, p = load_vint(data, body)
    assert block_type == 1  # precondition: the main header comes first
    flags, p = load_vint(data, p)
    if flags & 0x0001:
        _, p = load_vint(data, p)  # extra area size
    assert buf[p] & 0x04  # precondition: one-byte archive flags, solid set
    buf[p] &= ~0x04
    return fixup_rar_header_crcs(bytes(buf), broken=False)


def test_a_solid_flag_without_the_archive_bit_still_blocks_its_stream(
    tmp_path: Path,
) -> None:
    """The streams follow each member's solid flag, not the archive's solid bit, so
    ``b.txt`` is still refused as unsupported when the bit is clear. Members of
    later streams are left alone: ``unrar`` keys its decode-from-the-start on the
    archive bit (oracle below), so ``c.txt`` reads."""
    refusal = binary_refusal("unrar")
    if refusal is not None:
        pytest.skip(refusal)
    path = _solid_groups_first_member_v2(tmp_path)
    path.write_bytes(_main_solid_bit_cleared(path.read_bytes()))
    with open_archive(path, config=_config("unrar")) as archive:
        members = {m.name: m for m in archive.members()}
        with pytest.raises(UnsupportedFeatureError, match="in its solid stream"):
            _open_and_read(archive, members["b.txt"])
        assert len(_open_and_read(archive, members["c.txt"])) == 840


@pytest.mark.parametrize("in_pass", [False, True], ids=["open", "pass"])
def test_a_stored_member_after_an_unknown_version_still_reads(
    tmp_path: Path, in_pass: bool
) -> None:
    """archivey reads a stored, unencrypted member itself, so the members before
    it are not decoded and it reads. In a pass it is served as ``open()`` serves
    it, since ``unrar p`` writes nothing after the unknown member."""
    data = (_FIXTURES / "stored_solid_member__.rar").read_bytes()
    path = _write(tmp_path, "stored_after_v2.rar", _set_rar5_version(data, 0, 2))
    outcomes, _ = _read_outcomes(path, _config("unrar"), in_pass=in_pass)
    assert outcomes == {"first.txt": UnsupportedFeatureError, "second.bin": 2048}


def test_unar_refuses_only_the_unknown_members_solid_stream() -> None:
    """The ``unar`` policy refuses ``b.txt``, in ``a.txt``'s stream, with the
    reader's words, and leaves it out of its solid pass's run. ``c.txt`` and
    ``d.txt`` form a later stream, which ``unar`` reads."""
    data = (_FIXTURES / "solid_groups__.rar").read_bytes()
    archive = parse_rar_archive(io.BytesIO(_set_rar5_version(data, 0, 2)))
    policy = UnarRarPolicy(archive)
    _, b, c, d = archive.members
    refusal = policy.member_refusal(b)
    assert refusal is not None
    assert "'a.txt' in its solid stream" in refusal, refusal
    assert policy.solid_pass_refusal(b) == refusal
    for info in (c, d):
        assert policy.member_refusal(info) is None, info.filename
        assert policy.solid_pass_refusal(info) is None, info.filename


@requires_unrar_cli()
def test_unrar_stops_at_an_unknown_version_for_a_masked_read(tmp_path: Path) -> None:
    """The oracle. With the include mask archivey uses (``-n``), ``unrar p`` writes
    nothing for ``b.txt`` or for ``d.txt`` in the next solid group, and a
    whole-archive ``unrar p`` writes nothing. Only ``d.txt`` named as an argument,
    which archivey does not use, skips to its group."""
    path = _solid_groups_first_member_v2(tmp_path)

    def unrar_p(*args: str) -> bytes:
        return subprocess.run(
            ["unrar", "p", "-inul", *args],
            capture_output=True,
            check=False,
        ).stdout

    assert unrar_p("-n./b.txt", "--", str(path)) == b""
    assert unrar_p("-n./d.txt", "--", str(path)) == b""
    assert unrar_p("--", str(path)) == b""
    assert len(unrar_p("--", str(path), "d.txt")) == 840
    # With the archive's solid bit cleared, the masked read no longer decodes from
    # the start: ``c.txt``, which starts its own stream, reads. Nor does it decode a
    # skipped member, so ``d.txt``, which continues ``c.txt``'s stream by its own
    # solid flag, gets nothing. That archive is crafted (rar sets the bit with the
    # flags); archivey's length check reports the read as ``TruncatedError``, as on
    # this change's base, so no wrong bytes reach the caller.
    path.write_bytes(_main_solid_bit_cleared(path.read_bytes()))
    assert len(unrar_p("-n./c.txt", "--", str(path))) == 840
    assert unrar_p("-n./d.txt", "--", str(path)) == b""


@requires_binary("unar")
def test_unar_does_not_decode_the_stream_ahead_of_a_new_one(tmp_path: Path) -> None:
    """The oracle for ``unar``. With ``a.txt``'s packed data garbled, so nothing
    decodes it, ``unar -i`` still writes ``c.txt`` and ``d.txt`` whole and nothing
    for ``b.txt``, which shares ``a.txt``'s stream. A version change alone would not
    show this: ``unar`` ignores the version and decodes ``a.txt`` as it is."""
    data = (_FIXTURES / "solid_groups__.rar").read_bytes()
    a = parse_rar_archive(io.BytesIO(data)).members[0]
    garbled = bytearray(data)
    for at in range(a.data_offset, a.data_offset + a.compress_size):
        garbled[at] ^= 0x5A
    path = _write(tmp_path, "garbled.rar", bytes(garbled))
    expected = {
        info.filename: info.crc32
        for info in parse_rar_archive(io.BytesIO(data)).members
    }

    def unar_entry(index: int) -> bytes:
        return subprocess.run(
            ["unar", "-q", "-o", "-", "-i", str(path), str(index)],
            capture_output=True,
            check=False,
        ).stdout

    assert unar_entry(1) == b""
    for index, name in ((2, "c.txt"), (3, "d.txt")):
        assert zlib.crc32(unar_entry(index)) == expected[name], name


def test_the_reader_leaves_a_later_solid_group_to_unar(tmp_path: Path) -> None:
    """With ``unar`` chosen, the reader does not refuse ``d.txt`` itself: the read
    goes on to ``unar``. Where no accepted ``unar`` is installed, that shows as the
    missing-program error rather than the unsupported refusal;
    :func:`test_unar_reads_a_later_solid_group` reads it where one is."""
    if binary_refusal("unar") is None:
        pytest.skip("an accepted unar is installed; the read test covers it")
    with open_archive(
        _solid_groups_first_member_v2(tmp_path), config=_config("unar")
    ) as archive:
        member = next(m for m in archive.members() if m.name == "d.txt")
        with pytest.raises(PackageNotInstalledError):
            _open_and_read(archive, member)


def _basic_solid_rar4() -> RarArchive:
    """``basic_solid__rar4.rar``: ``empty_file.txt`` starts the solid stream, and
    ``file1.txt``, ``subdir/file2.txt`` and ``implicit_subdir/file3.txt`` continue
    it, all compressed. The tests edit its members in memory: no RAR 1.5-4 solid
    fixture has a compressed symlink, and ``rar`` 7 cannot write one."""
    archive = parse_rar_archive(
        io.BytesIO((_FIXTURES / "basic_solid__rar4.rar").read_bytes())
    )
    assert archive.is_solid
    return archive


def test_a_compressed_rar4_symlink_with_an_unknown_version_blocks_its_stream() -> None:
    """A RAR 2.x-4.x symlink stores its target as compressed data in the solid
    stream, so one with an unknown version blocks the members after it, as
    ``unar_dictionary_costs`` counts it in the stream. The symlink is no payload file,
    so it is not recorded itself."""
    archive = _basic_solid_rar4()
    link = archive.members[1]
    link.is_symlink = True
    link.extract_version = 36
    blocked = solid_after_unknown_compression(archive)
    assert id(link) not in blocked
    for info in archive.members[2:4]:
        block = blocked[id(info)]
        assert block.blocker is link and block.same_stream, info.filename


def test_a_compressed_rar4_symlink_without_the_solid_flag_starts_a_stream() -> None:
    """A compressed symlink with its solid flag clear starts a new stream, so the
    member after it is not in the unknown member's stream, and ``unar`` is not
    refused it."""
    archive = _basic_solid_rar4()
    blocker, link, after = archive.members[1:4]
    blocker.extract_version = 36
    link.is_symlink = True
    link.file_solid = False
    block = solid_after_unknown_compression(archive)[id(after)]
    assert block.blocker is blocker
    assert not block.same_stream
