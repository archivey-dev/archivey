"""The synthetic RAR writer: ``unrar`` reads each member as it does from the archive.

``rar_synthetic`` builds the small archive the reader will hand ``unrar`` instead of
the original (``openspec/changes/rar-synthetic-archives``). These tests build one
for every member with packed data in every committed RAR fixture (the member alone,
or its solid chain) and compare what ``unrar p`` prints with what the reader reads
from the original archive today.
"""

from __future__ import annotations

import os
import re
import stat
import struct
import zlib
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.exceptions import ArchiveyError, CorruptionError
from archivey.internal.backends import rar_synthetic as rs
from archivey.internal.backends.rar_parser import RarMemberInfo
from archivey.internal.backends.rar_reader import RarReader
from archivey.internal.backends.rar_unrar import open_unrar_p
from tests.conftest import requires_unrar_cli

_FIXTURES = Path(__file__).parent / "fixtures" / "rar"

_PASSWORDS = {
    "encrypted_header": "header_password",
    "tinyvol_hp": "header_password",
    "encryption": "password",
    "tinyvol_enc": "password",
    "symlinks_encrypted": "password",
    "wildcard_names_one_encrypted": "password",
}

# Listing raises: a volume of the set is cut or missing on purpose.
_UNLISTABLE = {"tinyvol_cut", "tinyvol_cut_solid"}


def _fixture_sets() -> Iterator[list[Path]]:
    for path in sorted(_FIXTURES.glob("*.rar")):
        first = re.fullmatch(r"(.*)\.part0*1\.rar", path.name)
        if first:
            if first.group(1) not in _UNLISTABLE:
                yield sorted(_FIXTURES.glob(f"{first.group(1)}.part*.rar"))
        elif re.fullmatch(r".*\.part\d+\.rar", path.name):
            continue
        elif path.name == "tinyvol_rnn.rar":
            yield [path, _FIXTURES / "tinyvol_rnn.r00"]
        else:
            yield [path]


def _password(path: Path) -> str | None:
    for prefix, password in _PASSWORDS.items():
        if path.name.startswith(prefix):
            return password
    return None


def _has_data(raw: RarMemberInfo) -> bool:
    return (
        raw.compress_size > 0
        and not raw.is_directory
        and not raw.is_file_copy()
        and not raw.is_symlink
    )


def _synthetic_read(
    reader: RarReader, raws: list[RarMemberInfo], target: int, password: str | None
) -> bytes:
    """Build the synthetic archive for ``raws[target]`` and return ``unrar p``'s output."""
    archive = reader._archive
    shared = reader._shared

    def read_at(offset: int, size: int) -> bytes:
        view = shared.view(offset, size)
        try:
            return view.read(size)
        finally:
            view.close()

    def header_key(salt: bytes, kdf_count: int | None) -> bytes | tuple[bytes, bytes]:
        assert password is not None
        if kdf_count is None:
            return reader._kdf_cache.rar3(password, salt)
        return reader._kdf_cache.rar5(password, salt, 1 << kdf_count)

    indices = rs.solid_chain(raws, target) if archive.is_solid else [target]
    chain = [i for i in indices if _has_data(raws[i])]
    members = []
    for position, index in enumerate(chain):
        raw = raws[index]
        (volume, offset, size), part_size, join = rs.member_headers(raw)
        header = rs.read_stored_header(
            read_at,
            archive,
            volume_index=volume,
            offset=offset,
            size=size,
            header_key=header_key if archive.has_header_encryption else None,
            excluded=reader._excluded,
        )
        rs.check_against_listing(header, raw, part_size=part_size)
        parts = raw.data_parts or [(raw.data_offset, raw.compress_size)]
        members.append(
            rs.SyntheticMember(
                rs.patch_header(
                    header,
                    name=rs.placeholder_name(position),
                    data_size=raw.compress_size,
                    join=join,
                ),
                lambda parts=parts: [(shared.view(o, n), n) for o, n in parts],
                raw.compress_size,
            )
        )
    synthetic = rs.SyntheticArchive(archive.version)
    try:
        synthetic.append(members)
        proc, stdout = open_unrar_p(
            synthetic.path,
            password=password,
            member=rs.placeholder_name(len(chain) - 1) if len(chain) > 1 else None,
            version_control=True,
            rar5=archive.version == 5,
        )
        with stdout:
            out = stdout.read()
        assert proc.wait() == 0
        return out
    finally:
        synthetic.close()


@requires_unrar_cli()
@pytest.mark.parametrize("volumes", list(_fixture_sets()), ids=lambda v: v[0].name)
def test_synthetic_read_matches_the_original(volumes: list[Path]) -> None:
    password = _password(volumes[0])
    source = volumes[0] if len(volumes) == 1 else volumes
    with open_archive(source, password=password) as reader:
        assert isinstance(reader, RarReader)
        members = list(reader.members())
        raws = [m._raw for m in members]
        assert all(isinstance(raw, RarMemberInfo) for raw in raws)
        compared = 0
        for index, member in enumerate(members):
            if not _has_data(raws[index]):
                continue
            try:
                with reader.open(member) as stream:
                    want = stream.read()
            except ArchiveyError:
                # Refused today (a name unrar cannot be given, a damaged member):
                # the synthetic read is still built, and must not fail to build.
                _synthetic_read(reader, raws, index, password)
                continue
            assert _synthetic_read(reader, raws, index, password) == want, member.name
            compared += 1
        if any(_has_data(raw) for raw in raws):
            assert compared, "no member compared"


def test_main_header_solid_flag_is_set_in_place() -> None:
    for version in (4, 5):
        plain = rs.main_header(version, solid=False)
        solid = rs.main_header(version, solid=True)
        assert len(plain) == len(solid)
        assert plain != solid


def _stub_member(version: int, data: bytes) -> rs.SyntheticMember:
    return rs.SyntheticMember(
        header=b"H" * 10, data=lambda: [(BytesIO(data), len(data))], data_size=len(data)
    )


def test_append_writes_each_member_once_and_moves_endarc() -> None:
    synthetic = rs.SyntheticArchive(5)
    try:
        assert stat.S_IMODE(os.stat(synthetic.path).st_mode) == 0o600
        empty = rs.SyntheticArchive.overhead(5)
        assert synthetic.size == empty == synthetic.path.stat().st_size
        synthetic.append([_stub_member(5, b"a" * 5)])
        assert synthetic.count == 1
        assert synthetic.size == empty + 15 == synthetic.path.stat().st_size
        data = synthetic.path.read_bytes()
        assert data.endswith(rs.end_header(5))
        assert data[8:].startswith(rs.main_header(5, solid=False))
        synthetic.append([_stub_member(5, b"b" * 3)])
        data = synthetic.path.read_bytes()
        assert synthetic.size == empty + 28 == len(data)
        assert data[8:].startswith(rs.main_header(5, solid=True))
        assert data.count(rs.end_header(5)) == 1
        assert b"HHHHHHHHHHaaaaaHHHHHHHHHHbbb" in data
    finally:
        synthetic.close()
    assert not synthetic.path.exists()
    synthetic.close()


def test_append_cut_short_keeps_the_file_as_it_was() -> None:
    synthetic = rs.SyntheticArchive(4)
    try:
        synthetic.append([_stub_member(4, b"x")])
        before = synthetic.path.read_bytes()
        short = rs.SyntheticMember(
            header=b"H", data=lambda: [(BytesIO(b"ab"), 5)], data_size=5
        )
        with pytest.raises(ArchiveyError):
            synthetic.append([short])
        assert synthetic.path.read_bytes() == before
        assert synthetic.count == 1
    finally:
        synthetic.close()


def _rar3_file_header(
    *, flags: int = 0x8000, name: bytes = b"a.txt", pack: int = 3, crc: int = 7
) -> bytes:
    fields = struct.pack("<LLBLLBBHL", pack, 3, 3, crc, 0, 29, 0x33, len(name), 0)
    rest = fields + name
    body = struct.pack("<BHH", 0x74, flags, 7 + len(rest)) + rest
    return struct.pack("<H", zlib.crc32(body) & 0xFFFF) + body


def test_rar3_patch_renames_and_clears_split_and_unicode() -> None:
    raw = _rar3_file_header(flags=0x8000 | 0x0200 | 0x0003, name=b"a.txt\x00\x01\x02")
    header = rs.parse_stored_header(4, raw)
    assert header.split
    patched = rs.parse_stored_header(
        4, rs.patch_header(header, name="m0", data_size=9, join=True)
    )
    flags = struct.unpack_from("<H", patched.raw, 3)[0]
    assert not flags & 0x0203
    assert patched.data_size == 9
    assert patched.raw.endswith(b"m0")
    assert patched.crc32 == 7


def test_rar3_join_past_4_gib_without_large_fields_is_unsupported() -> None:
    header = rs.parse_stored_header(4, _rar3_file_header())
    with pytest.raises(rs.SyntheticUnsupported):
        rs.patch_header(header, name="m0", data_size=1 << 32, join=True)


def test_rar3_service_header_keeps_its_name() -> None:
    raw = bytearray(_rar3_file_header(name=b"CMT"))
    raw[2] = 0x7A
    struct.pack_into("<H", raw, 0, zlib.crc32(raw[2:]) & 0xFFFF)
    header = rs.parse_stored_header(4, bytes(raw))
    assert rs.patch_header(header, name="m0", data_size=3, join=False).endswith(b"CMT")


def test_damaged_header_and_listing_mismatch_raise() -> None:
    raw = bytearray(_rar3_file_header())
    raw[-1] ^= 1
    with pytest.raises(CorruptionError):
        rs.parse_stored_header(4, bytes(raw))
    header = rs.parse_stored_header(4, _rar3_file_header(crc=7))
    member = RarMemberInfo.__new__(RarMemberInfo)
    member.size_unknown = False
    member.file_size = 3
    member.crc32 = 8
    with pytest.raises(CorruptionError, match="CRC32"):
        rs.check_against_listing(header, member, part_size=3)
    member.crc32 = 7
    rs.check_against_listing(header, member, part_size=3)
    with pytest.raises(CorruptionError, match="packed size"):
        rs.check_against_listing(header, member, part_size=4)
