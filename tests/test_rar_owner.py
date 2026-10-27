"""The RAR owner records (``rar -ow``) fill uid, gid, uname and gname.

RAR5 keeps the owner in a file header extra record; RAR 1.5-4 in a ``UOW`` service
header right after the file. The malformed-record case is in
``test_rar_header_record_leniency.py`` with the other extra records.
"""

from __future__ import annotations

import io
import os
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

import pytest

from archivey import open_archive
from archivey.config import ArchiveyConfig, ListingLimits
from archivey.diagnostics import DiagnosticCode, DiagnosticPolicy
from archivey.exceptions import ArchiveyError, ResourceLimitError
from archivey.internal.listing_limits import member_metadata_bytes
from tests.conftest import requires_binary
from tests.test_audit_rar_iso_dir import _rar3_build, _rar3_parse

_RAR_FIXTURES = Path(__file__).parent / "fixtures" / "rar"

# One member ``a.txt`` ("hi\n"), written with ``-ow`` on Linux. RAR 7.00 stores the
# owner's names when the system resolves them and the numeric ids otherwise. RAR 6.23
# with ``-ma4`` stores names only, and writes no UOW header when there are none.
OWNER_NAMES_RAR5 = bytes.fromhex(
    "526172211a0701003392b5e50a010506000501018080006fdfc2fd300203188300048300a483027a"
    "7a6fed80000105612e7478740a031364d7d06a9e3ac2200c060304726f6f7404726f6f7468690a1d"
    "77565103050400"
)
OWNER_IDS_RAR5 = bytes.fromhex(  # owned by 1234:5678, which has no names
    "526172211a0701003392b5e50a01050600050101808000b6b3f52a2a0203128300048300a483027a"
    "7a6fed80000105612e7478740a031364d7d06a9e3ac22006060cd209ae2c68690a1d775651030504"
    "00"
)
OWNER_NAMES_RAR4 = bytes.fromhex(
    "526172211a0700cf907300000d00000000000000ee457420902a000300000003000000037a7a6fed"
    "d66c4f5d1d300500a4810000612e74787400b0bfdc5368690ad1d17a10802c000000000000000000"
    "0300000000e56e4f5d1d30030000000000554f57726f6f7400726f6f74c43d7b00400700"
)


@pytest.mark.parametrize(
    ("data", "owner"),
    [
        pytest.param(OWNER_NAMES_RAR5, (None, None, "root", "root"), id="rar5-names"),
        pytest.param(OWNER_IDS_RAR5, (1234, 5678, None, None), id="rar5-ids"),
        pytest.param(OWNER_NAMES_RAR4, (None, None, "root", "root"), id="rar4-names"),
    ],
)
def test_owner_record_fills_the_owner_fields(
    data: bytes, owner: tuple[int | None, int | None, str | None, str | None]
) -> None:
    with open_archive(io.BytesIO(data)) as archive:
        (member,) = archive.members()
        assert (member.uid, member.gid, member.uname, member.gname) == owner
        assert not member.diagnostics
        assert archive.read(member) == b"hi\n"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(OWNER_NAMES_RAR5, id="rar5"),
        pytest.param(OWNER_NAMES_RAR4, id="rar4"),
    ],
)
def test_owner_names_count_at_parse(data: bytes) -> None:
    # The header walk weighs what the member table keeps before any member is
    # registered; the owner names are part of it, so the walk refuses first.
    with open_archive(io.BytesIO(data)) as archive:
        (member,) = archive.members()
    weight = member_metadata_bytes(member)
    assert weight == 2 * len("a.txt") + len("root") + len("root")

    def limited(max_metadata_bytes: int) -> ArchiveyConfig:
        return ArchiveyConfig(
            listing_limits=ListingLimits(max_metadata_bytes=max_metadata_bytes)
        )

    with pytest.raises(ResourceLimitError, match=r"RAR headers of \d+ members hold"):
        open_archive(io.BytesIO(data), config=limited(weight - 1))
    with open_archive(io.BytesIO(data), config=limited(weight)) as archive:
        assert archive.members()[0].uname == "root"


@requires_binary("rar")
@pytest.mark.skipif(not hasattr(os, "getuid"), reason="needs Unix owners")
def test_rar_ow_records_the_current_owner(tmp_path: Path) -> None:
    import grp
    import pwd

    (tmp_path / "a.txt").write_bytes(b"data")
    st = (tmp_path / "a.txt").stat()
    try:
        uname = pwd.getpwuid(st.st_uid).pw_name
        gname = grp.getgrgid(st.st_gid).gr_name
    except KeyError:
        pytest.skip("the file's owner has no name, so rar stores numeric ids")
    subprocess.run(
        ["rar", "a", "-ow", "-idq", "a.rar", "a.txt"], cwd=tmp_path, check=True
    )
    with open_archive(tmp_path / "a.rar") as archive:
        member = archive.get("a.txt")
        assert (member.uname, member.gname) == (uname, gname)
        # With names to store, rar stores no ids.
        assert (member.uid, member.gid) == (None, None)


_RAR3_SALT = 0x0400
_RAR3_SUB = 0x7A
_RAR3_ENDARC = 0x7B


def _uow_block(data: bytes = OWNER_NAMES_RAR4) -> dict[str, Any]:
    (block,) = [
        b for b in _rar3_parse(data) if b["type"] == _RAR3_SUB and b"UOW" in b["header"]
    ]
    return block


def _with_uow_header(sub_data: bytes, *, salt: bytes = b"") -> bytes:
    """``OWNER_NAMES_RAR4`` with the UOW header's data replaced, then ``salt``."""
    blocks = _rar3_parse(OWNER_NAMES_RAR4)
    block = next(b for b in blocks if b["type"] == _RAR3_SUB)
    header = block["header"]
    name_end = 32 + struct.unpack_from("<H", header, 26)[0]
    header[name_end:] = sub_data + salt
    if salt:
        flags = struct.unpack_from("<H", header, 3)[0]
        struct.pack_into("<H", header, 3, flags | _RAR3_SALT)
    struct.pack_into("<H", header, 5, len(header))
    return _rar3_build(blocks)


@pytest.mark.parametrize(
    ("sub_data", "salt", "names"),
    [
        # unrar reads a service header's data before its salt (``ReadHeader15``).
        pytest.param(b"root\0root", b"S" * 8, ("root", "root"), id="salted"),
        # The group name ends at a NUL, as ``getgrnam`` reads it.
        pytest.param(b"user\0group\0pad", b"", ("user", "group"), id="trailing-nul"),
        # With no NUL ``unrar`` applies no owner (``ExtractUnixOwner30``).
        pytest.param(b"root", b"", (None, None), id="no-nul"),
    ],
)
def test_rar4_uow_data_reads_as_unrar_reads_it(
    sub_data: bytes, salt: bytes, names: tuple[str | None, str | None]
) -> None:
    data = _with_uow_header(sub_data, salt=salt)
    with open_archive(io.BytesIO(data)) as archive:
        (member,) = archive.members()
        assert (member.uname, member.gname) == names
        assert archive.read(member) == b"hi\n"
        # A header that names no owner is dropped as a malformed record is.
        codes = [d.code for d in member.diagnostics]
        expected = [] if names[0] else [DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED]
        assert codes == expected


def test_rar4_uow_without_an_owner_is_refused_under_strict() -> None:
    data = _with_uow_header(b"root")
    with (
        pytest.raises(
            ArchiveyError, match="UOW owner header has no NUL in its owner data, so"
        ),
        open_archive(
            io.BytesIO(data),
            config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
        ) as archive,
    ):
        archive.members()


def test_rar4_stacked_uow_headers_report_once() -> None:
    # A writer puts one UOW after a file; a stack of crafted ones reports once.
    blocks = _rar3_parse(_with_uow_header(b"root"))
    uow = next(i for i, b in enumerate(blocks) if b["type"] == _RAR3_SUB)
    blocks[uow:uow] = [blocks[uow]] * 20
    with open_archive(io.BytesIO(_rar3_build(blocks))) as archive:
        (member,) = archive.members()
        assert [d.code for d in member.diagnostics] == [
            DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED
        ]


@pytest.mark.parametrize("first_has_owner", [True, False])
def test_rar4_uow_with_an_owner_beats_one_without(first_has_owner: bool) -> None:
    # unrar applies the owner of whichever UOW header names one, so the member has an
    # owner and no report that it is listed without one, in either order.
    blocks = _rar3_parse(_with_uow_header(b"root"))
    uow = next(i for i, b in enumerate(blocks) if b["type"] == _RAR3_SUB)
    blocks.insert(uow + (0 if first_has_owner else 1), _uow_block())
    with open_archive(io.BytesIO(_rar3_build(blocks))) as archive:
        (member,) = archive.members()
        assert (member.uname, member.gname) == ("root", "root")
        assert not member.diagnostics


@pytest.mark.parametrize(
    ("sub_data", "names", "codes"),
    [
        pytest.param(b"root\0root", ("root", "root"), [], id="owner"),
        pytest.param(
            b"root",
            (None, None),
            [DiagnosticCode.MEMBER_HEADER_RECORD_SKIPPED],
            id="no-nul",
        ),
    ],
)
def test_rar4_owner_after_the_last_part_of_a_split_member(
    tmp_path: Path,
    sub_data: bytes,
    names: tuple[str | None, str | None],
    codes: list[DiagnosticCode],
) -> None:
    # rar 6.23 -ma4 -ow -v writes the UOW header after a split member's last part,
    # in the last volume; the merged member keeps it, or the report of it.
    for name in ("tinyvol_rnn.rar", "tinyvol_rnn.r00"):
        shutil.copy(_RAR_FIXTURES / name, tmp_path / name)
    last = tmp_path / "tinyvol_rnn.r00"
    blocks = _rar3_parse(last.read_bytes())
    end = next(i for i, b in enumerate(blocks) if b["type"] == _RAR3_ENDARC)
    blocks.insert(end, _uow_block(_with_uow_header(sub_data)))
    last.write_bytes(_rar3_build(blocks))
    with open_archive(tmp_path / "tinyvol_rnn.rar") as archive:
        # One file, split across both volumes: 1600 bytes only if both parts join.
        (split,) = [m for m in archive.members() if m.is_file]
        assert split.name == "payload.bin"
        assert (split.uname, split.gname) == names
        assert [d.code for d in split.diagnostics] == codes
        assert len(archive.read(split)) == 1600
