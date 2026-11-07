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
import subprocess
import zlib
from collections.abc import Iterator
from io import BytesIO
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, DecoderLimits, SpoolLimits, open_archive
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
)
from archivey.internal.backends import rar_reader as rr, rar_synthetic as rs
from archivey.internal.backends.rar_parser import (
    RarArchive,
    RarKdfCache,
    RarMemberInfo,
    parse_rar_archive,
)
from archivey.internal.backends.rar_reader import RarReader
from archivey.internal.backends.rar_unrar import open_unrar_p
from archivey.internal.streams.streamtools.solid import SolidBlockReader
from tests.conftest import requires, requires_binary, requires_unrar_cli

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


def _fixture_params() -> Iterator[object]:
    for volumes in _fixture_sets():
        # Listing needs the header key, which takes AES (the cryptography package).
        if _password(volumes[0]) == "header_password":
            yield pytest.param(volumes, marks=requires("cryptography"))
        else:
            yield volumes


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

    keys = rs.HeaderKeys(reader._kdf_cache, password) if password is not None else None

    indices = rs.solid_chain(raws, target) if archive.is_solid else [target]
    chain = [i for i in indices if rs.has_packed_data(raws[i])]
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
            header_keys=keys if archive.has_header_encryption else None,
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
    synthetic = rs.SyntheticArchive(archive.version, solid=len(chain) > 1)
    try:
        synthetic.append(members)
        proc, stdout = open_unrar_p(
            synthetic.path,
            password=password,
            # A solid read always names its target, as the reader does.
            member=(
                rs.placeholder_mask(len(chain) - 1, raws[target], archive.version)
                if archive.is_solid
                else None
            ),
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
@pytest.mark.parametrize("volumes", list(_fixture_params()), ids=lambda v: v[0].name)
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
            if not rs.has_packed_data(raws[index]):
                continue
            if raws[index].is_symlink:
                # In a chain only: open() of a link reads its target's bytes.
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
        if any(rs.has_packed_data(raw) for raw in raws):
            assert compared, "no member compared"


def test_main_header_solid_flag_is_set_in_place() -> None:
    for version in (4, 5):
        plain = rs.main_header(version, solid=False)
        solid = rs.main_header(version, solid=True)
        assert len(plain) == len(solid)
        assert plain != solid


def _stub_member(data: bytes) -> rs.SyntheticMember:
    return rs.SyntheticMember(
        header=b"H" * 10, data=lambda: [(BytesIO(data), len(data))], data_size=len(data)
    )


def test_append_writes_each_member_once_and_moves_endarc() -> None:
    synthetic = rs.SyntheticArchive(5, solid=True)
    try:
        if os.name == "posix":
            assert stat.S_IMODE(os.stat(synthetic.path).st_mode) == 0o600
        empty = rs.SyntheticArchive.overhead(5)
        assert synthetic.size == empty == synthetic.path.stat().st_size
        synthetic.append([_stub_member(b"a" * 5)])
        assert synthetic.count == 1
        assert synthetic.size == empty + 15 == synthetic.path.stat().st_size
        data = synthetic.path.read_bytes()
        assert data.endswith(rs.end_header(5))
        assert data[8:].startswith(rs.main_header(5, solid=False))
        synthetic.append([_stub_member(b"b" * 3)])
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
        synthetic.append([_stub_member(b"x")])
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


def test_nonsolid_file_keeps_main_plain() -> None:
    synthetic = rs.SyntheticArchive(5)
    try:
        synthetic.append([_stub_member(b"a"), _stub_member(b"b")])
        assert synthetic.path.read_bytes()[8:].startswith(
            rs.main_header(5, solid=False)
        )
    finally:
        synthetic.close()


def test_append_refuses_data_that_does_not_add_up_and_closes_streams() -> None:
    synthetic = rs.SyntheticArchive(5)
    streams = [BytesIO(b"abcdef"), BytesIO(b"z")]
    try:
        before = synthetic.path.read_bytes()
        wrong = rs.SyntheticMember(
            header=b"H", data=lambda: [(streams[0], 6), (streams[1], 1)], data_size=1
        )
        with pytest.raises(ValueError, match="does not add up"):
            synthetic.append([wrong])
        assert synthetic.path.read_bytes() == before
        assert all(stream.closed for stream in streams)
        cut = [BytesIO(b"ab"), BytesIO(b"later")]
        short = rs.SyntheticMember(
            header=b"H", data=lambda: [(cut[0], 5), (cut[1], 5)], data_size=10
        )
        with pytest.raises(ArchiveyError):
            synthetic.append([short])
        assert all(stream.closed for stream in cut)
    finally:
        synthetic.close()


def _fixture_archive(name: str, password: str | None = None) -> RarArchive:
    with (_FIXTURES / name).open("rb") as f:
        return parse_rar_archive(f, password=password)


def _reader_of(path: Path):
    data = path.read_bytes()
    return lambda offset, size: data[offset : offset + size]


@requires("cryptography")
def test_encrypted_header_needs_a_key() -> None:
    archive = _fixture_archive("encrypted_header__.rar", "header_password")
    member = archive.members[0]
    with pytest.raises(ValueError, match="header_keys"):
        rs.read_stored_header(
            _reader_of(_FIXTURES / "encrypted_header__.rar"),
            archive,
            volume_index=0,
            offset=member.header_offset,
            size=member.header_size,
            excluded=frozenset(),
        )


@requires("cryptography")
def test_rar5_volume_without_its_crypt_record_is_corrupt() -> None:
    archive = _fixture_archive("encrypted_header__.rar", "header_password")
    member = archive.members[0]
    with pytest.raises(CorruptionError, match="volume 2"):
        rs.read_stored_header(
            _reader_of(_FIXTURES / "encrypted_header__.rar"),
            archive,
            volume_index=1,
            offset=member.header_offset,
            size=member.header_size,
            header_keys=rs.HeaderKeys(RarKdfCache(), "header_password"),
            excluded=frozenset(),
        )


def test_short_header_reread_is_truncated() -> None:
    archive = _fixture_archive("basic_nonsolid__.rar")
    member = archive.members[0]
    with pytest.raises(TruncatedError):
        rs.read_stored_header(
            lambda offset, size: b"\x00" * (size - 1),
            archive,
            volume_index=0,
            offset=member.header_offset,
            size=member.header_size,
            excluded=frozenset(),
        )


def test_rar5_service_header_keeps_its_name() -> None:
    fields = _vint(0) + _vint(3) + _vint(0) + _vint(0x30 << 0) + _vint(0)
    body = _vint(3) + _vint(0x02) + _vint(3) + fields + _vint(3) + b"CMT"
    raw = rs._rar5_block(body)
    header = rs.parse_stored_header(5, raw)
    patched = rs.patch_header(header, name="m0", data_size=3, join=False)
    assert patched.endswith(b"CMT")
    assert rs.parse_stored_header(5, patched).data_size == 3


def _vint(value: int) -> bytes:
    return rs._vint(value)


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


# ------------------------------------------------------------------- reader route


class _TempSpy:
    """Every synthetic archive a test's reads make, with its size when made full."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.paths: list[Path] = []
        self.sizes: list[int] = []
        real = rs.SyntheticArchive.append

        def append(synthetic: rs.SyntheticArchive, members: object) -> None:
            real(synthetic, members)  # type: ignore[arg-type]
            self.paths.append(synthetic.path)
            self.sizes.append(synthetic.size)

        monkeypatch.setattr(rs.SyntheticArchive, "append", append)


@pytest.fixture
def synthetic_spy(monkeypatch: pytest.MonkeyPatch) -> _TempSpy:
    return _TempSpy(monkeypatch)


@requires_unrar_cli()
@pytest.mark.parametrize(
    ("fixture", "name"),
    [
        ("wildcard_names__.rar", "a*.txt"),
        ("wildcard_names__rar4.rar", "a*.txt"),
        ("wildcard_names__.rar", "b?.txt"),
        ("wildcard_dirglob__.rar", "d*/x.txt"),
        ("wildcard_backslash__.rar", "a/b*.txt"),
        ("wildcard_backslash__.rar", "a/b_TGT.txt"),
    ],
)
def test_names_the_mask_refused_read_through_a_synthetic_archive(
    fixture: str, name: str, synthetic_spy: _TempSpy
) -> None:
    """A name never reaches unrar, so a glob, a directory glob or a backslash in it
    reads the member's own bytes, with no config flag."""
    with open_archive(_FIXTURES / fixture) as reader:
        data = reader.read(name)
        member = reader.get(name)
    assert len(data) == member.size
    assert len(synthetic_spy.paths) == 1
    assert not synthetic_spy.paths[0].exists()


@requires_unrar_cli()
def test_stream_source_copies_the_member_not_the_archive(
    synthetic_spy: _TempSpy,
) -> None:
    raw = (_FIXTURES / "wildcard_names__.rar").read_bytes()
    with open_archive(BytesIO(raw)) as reader:
        assert len(reader.read("b1.txt")) == reader.get("b1.txt").size
        packed = reader.get("b1.txt")._raw.compress_size
    (size,) = synthetic_spy.sizes
    assert packed < size < packed + 200 < len(raw)


@requires_unrar_cli()
def test_backward_seek_respawns_on_the_same_file(synthetic_spy: _TempSpy) -> None:
    with open_archive(_FIXTURES / "wildcard_names__.rar", seekable_members=True) as r:
        with r.open(r.get("b1.txt")) as stream:
            first = stream.read()
            stream.seek(0)
            assert stream.read() == first
            assert len(synthetic_spy.paths) == 1
            assert synthetic_spy.paths[0].exists()
        assert not synthetic_spy.paths[0].exists()


@requires_unrar_cli()
def test_large_member_of_a_file_on_disk_keeps_the_original(
    monkeypatch: pytest.MonkeyPatch, synthetic_spy: _TempSpy
) -> None:
    from archivey.internal.backends import rar_reader

    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    with open_archive(_FIXTURES / "wildcard_names__.rar") as reader:
        assert reader.read("b1.txt")
    assert synthetic_spy.paths == []


@requires_unrar_cli()
def test_header_changed_after_open_is_refused_before_unrar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.backends import rar_reader

    def refuse(*args: object, **kwargs: object) -> object:
        raise AssertionError("unrar was spawned")

    raw = bytearray((_FIXTURES / "wildcard_names__.rar").read_bytes())
    source = BytesIO(raw)
    with open_archive(source) as reader:
        info = reader.get("b1.txt")._raw
        assert isinstance(info, RarMemberInfo)
        monkeypatch.setattr(rar_reader, "open_unrar_p", refuse)
        # One byte inside the stored header, past its CRC: the CRC now fails.
        source.getbuffer()[info.header_offset + 8] ^= 0xFF
        with pytest.raises(CorruptionError):
            reader.read("b1.txt")


@requires_unrar_cli()
def test_reader_close_removes_a_file_left_by_an_open_stream(
    synthetic_spy: _TempSpy,
) -> None:
    reader = open_archive(_FIXTURES / "wildcard_names__.rar")
    stream = reader.open(reader.get("b1.txt"))
    stream.read(1)
    (path,) = synthetic_spy.paths
    assert path.exists()
    reader.close()
    assert not path.exists()
    stream.close()


def _limited(max_bytes: int) -> ArchiveyConfig:
    return ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=max_bytes))


def _stream_reader(fixture: str, max_bytes: int) -> RarReader:
    raw = (_FIXTURES / fixture).read_bytes()
    reader = open_archive(BytesIO(raw), config=_limited(max_bytes))
    assert isinstance(reader, RarReader)
    return reader


def _member_copy(reader: RarReader, name: str) -> object:
    member = reader.get(name)
    assert isinstance(member._raw, RarMemberInfo)
    return reader._synthetic_file(member, member._raw)


def test_a_member_over_the_spool_limit_does_not_refuse_the_next() -> None:
    """A member copy refused for its size records nothing: a smaller one still fits.

    The copies cost 73, 76 and 72 bytes for the three files. Nothing is spawned or
    written: the charge is taken before the first spawn.
    """
    with _stream_reader("basic_nonsolid__.rar", 75) as reader:
        with pytest.raises(ResourceLimitError, match="76 bytes"):
            _member_copy(reader, "subdir/file2.txt")
        small = _member_copy(reader, "implicit_subdir/file3.txt")
        assert small is not None


def test_a_member_refused_beside_another_copy_fits_once_that_closes() -> None:
    with _stream_reader("basic_nonsolid__.rar", 76 + 72 - 1) as reader:
        big = _member_copy(reader, "subdir/file2.txt")
        assert big is not None
        with pytest.raises(ResourceLimitError, match="72 bytes on top of 76"):
            _member_copy(reader, "implicit_subdir/file3.txt")
        big.close()  # type: ignore[attr-defined]
        assert _member_copy(reader, "implicit_subdir/file3.txt") is not None


@requires_unrar_cli()
def test_password_probe_removes_its_copy_before_the_read(
    synthetic_spy: _TempSpy,
) -> None:
    """The probe's synthetic archive is gone once the candidate is chosen, so the
    read's own copy fits a limit that holds one copy of the member (106 bytes) but
    not two."""
    raw = (_FIXTURES / "encryption__rar4.rar").read_bytes()
    with open_archive(
        BytesIO(raw), password=["wrong", "password"], config=_limited(150)
    ) as reader:
        member = reader.get("secret.txt")
        assert len(reader.read(member)) == member.size
        assert len(synthetic_spy.paths) >= 2
        assert not any(path.exists() for path in synthetic_spy.paths)


# ------------------------------------------------------------------ solid streams


class _AppendSpy:
    """Each append to a synthetic archive: which file, and how many members."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.appends: list[tuple[Path, int]] = []
        real = rs.SyntheticArchive.append

        def append(synthetic: rs.SyntheticArchive, members: object) -> None:
            members = list(members)  # type: ignore[call-overload]
            real(synthetic, members)
            self.appends.append((synthetic.path, len(members)))

        monkeypatch.setattr(rs.SyntheticArchive, "append", append)

    def files(self) -> set[Path]:
        return {path for path, _ in self.appends}


@pytest.fixture
def append_spy(monkeypatch: pytest.MonkeyPatch) -> _AppendSpy:
    return _AppendSpy(monkeypatch)


_SOLID_FILES = ["file1.txt", "subdir/file2.txt", "implicit_subdir/file3.txt"]


def _expected(fixture: str) -> dict[str, bytes]:
    with open_archive(_FIXTURES / fixture) as reader:
        return {
            m.name: reader.read(m)
            for m in reader.members()
            if m.is_file and m.name in _SOLID_FILES
        }


@requires_unrar_cli()
@pytest.mark.parametrize("fixture", ["basic_solid__.rar", "basic_solid__rar4.rar"])
def test_a_solid_stream_grows_and_is_copied_once(
    fixture: str, append_spy: _AppendSpy
) -> None:
    """Reads further into the stream append only the members between; a read of a
    member already in the file copies nothing. One file for the reader."""
    expected = _expected(fixture)
    append_spy.appends.clear()
    with open_archive(_FIXTURES / fixture) as reader:
        assert reader.read("subdir/file2.txt") == expected["subdir/file2.txt"]
        # The stream start (an empty file with packed bytes), file1, file2.
        first = append_spy.appends[-1][1]
        assert reader.read("file1.txt") == expected["file1.txt"]
        assert len(append_spy.appends) == 1
        last = "implicit_subdir/file3.txt"
        assert reader.read(last) == expected[last]
        assert [n for _, n in append_spy.appends] == [first, 1]
        (path,) = append_spy.files()
        assert path.exists()
    assert not path.exists()


@requires_unrar_cli()
def test_a_solid_stream_source_is_not_copied_whole(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(self: RarReader) -> Path:
        raise AssertionError("the whole archive was copied")

    monkeypatch.setattr(RarReader, "_ensure_archive_path", refuse)
    expected = _expected("basic_solid__.rar")
    raw = (_FIXTURES / "basic_solid__.rar").read_bytes()
    with open_archive(BytesIO(raw)) as reader:
        for name in reversed(_SOLID_FILES):
            assert reader.read(name) == expected[name]


@requires_unrar_cli()
def test_a_read_further_in_while_the_stream_is_held_starts_a_new_generation(
    append_spy: _AppendSpy,
) -> None:
    """``unrar`` may still be reading the stream's file (and on Windows holds it
    with read sharing only), so it is not appended to. A read further in starts a
    new file for the stream, which later reads extend; the held one is removed
    when its read closes."""
    expected = _expected("basic_solid__.rar")
    append_spy.appends.clear()
    with open_archive(
        _FIXTURES / "basic_solid__.rar", concurrent_operations=True
    ) as reader:
        assert isinstance(reader, RarReader)
        with reader.open("file1.txt") as held:
            assert held.read(1) == expected["file1.txt"][:1]
            (old,) = append_spy.files()
            assert reader.read("subdir/file2.txt") == expected["subdir/file2.txt"]
            (new,) = append_spy.files() - {old}
            last = "implicit_subdir/file3.txt"
            assert reader.read(last) == expected[last]
            # The new file grew by the one member; the held one is untouched.
            assert [path for path, _ in append_spy.appends] == [old, new, new]
            assert append_spy.appends[-1][1] == 1
            assert old.exists()
            assert held.read() == expected["file1.txt"][1:]
        assert not old.exists()
        assert reader._retired_streams == set()
        budget = reader._spool_budget(None)
        assert budget._written == reader._solid_streams[0].charge
        # Already in the new file: nothing is copied.
        assert reader.read(last) == expected[last]
        assert len(append_spy.appends) == 3
        assert new.exists()
    assert not new.exists()


def test_a_solid_stream_copy_over_the_spool_limit_is_refused_and_not_recorded() -> None:
    """A stream source cannot fall back: the copy up to the member raises, and a
    read nearer the stream start that fits still copies (nothing is spawned here)."""
    raw = (_FIXTURES / "basic_solid__.rar").read_bytes()
    with open_archive(BytesIO(raw), config=_limited(0)) as reader:
        assert isinstance(reader, RarReader)
        member = reader.get("file1.txt")
        assert isinstance(member._raw, RarMemberInfo)
        with pytest.raises(ResourceLimitError, match="solid stream"):
            reader._synthetic_file(member, member._raw)
    overhead = rs.SyntheticArchive.overhead(5)
    with open_archive(BytesIO(raw)) as reader:
        assert isinstance(reader, RarReader)
        sizes = {}
        for name in ("file1.txt", "implicit_subdir/file3.txt"):
            member = reader.get(name)
            assert isinstance(member._raw, RarMemberInfo)
            read = reader._synthetic_file(member, member._raw)
            assert read is not None
            read.close()
            sizes[name] = reader._solid_streams[0].charge
    limit = sizes["file1.txt"] + 1
    assert limit < sizes["implicit_subdir/file3.txt"]
    assert sizes["file1.txt"] > overhead
    with open_archive(BytesIO(raw), config=_limited(limit)) as reader:
        assert isinstance(reader, RarReader)
        far = reader.get("implicit_subdir/file3.txt")
        near = reader.get("file1.txt")
        assert isinstance(far._raw, RarMemberInfo)
        assert isinstance(near._raw, RarMemberInfo)
        with pytest.raises(ResourceLimitError):
            reader._synthetic_file(far, far._raw)
        read = reader._synthetic_file(near, near._raw)
        assert read is not None
        read.close()


def test_a_solid_member_of_a_large_stream_on_disk_keeps_the_original(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from archivey.internal.backends import rar_reader

    monkeypatch.setattr(rar_reader, "_SYNTHETIC_IN_PLACE_THRESHOLD", 0)
    with open_archive(_FIXTURES / "basic_solid__.rar") as reader:
        assert isinstance(reader, RarReader)
        member = reader.get("file1.txt")
        assert isinstance(member._raw, RarMemberInfo)
        assert reader._synthetic_file(member, member._raw) is None
        assert 0 not in reader._solid_streams


def test_the_chain_dictionary_counts_the_stream_alone() -> None:
    """In ``solid_groups__.rar`` a member of a later group is charged its own
    group's window and bytes, not the archive's from its start."""
    with open_archive(_FIXTURES / "solid_groups__.rar") as reader:
        assert isinstance(reader, RarReader)
        from archivey.internal.backends.rar_reader import _chain_dictionary_cost

        members = reader._archive.members
        last = len(members) - 1
        span = rs.solid_chain(members, last)
        assert span.start > 0, "the fixture's last member starts a later group"
        cost = _chain_dictionary_cost(members, span)
        assert cost.count <= sum(members[i].file_size for i in span)
        assert cost.declarer >= span.start


# --------------------------------------------------------------- solid pass


class _LiveFiles:
    """Synthetic archives made and removed; the most on disk at once."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.made = 0
        self.live = 0
        self.peak = 0
        real_init = rs.SyntheticArchive.__init__
        real_close = rs.SyntheticArchive.close

        def init(synthetic: rs.SyntheticArchive, *args: object, **kw: object) -> None:
            real_init(synthetic, *args, **kw)  # type: ignore[arg-type]
            self.made += 1
            self.live += 1
            self.peak = max(self.peak, self.live)

        def close(synthetic: rs.SyntheticArchive) -> None:
            if synthetic.path.exists():
                self.live -= 1
            real_close(synthetic)

        monkeypatch.setattr(rs.SyntheticArchive, "__init__", init)
        monkeypatch.setattr(rs.SyntheticArchive, "close", close)


def _pass_bytes(source: object, **kwargs: object) -> dict[str, bytes]:
    with open_archive(source, **kwargs) as reader:  # type: ignore[arg-type]
        return {
            member.name: stream.read()
            for member, stream in reader.stream_members()
            if stream is not None and member.is_file
        }


# Below twice the run cap, so every solid stream runs on its own.
_ONE_STREAM_PER_RUN = 2 * rr._SYNTHETIC_IN_PLACE_THRESHOLD - 1


def _refuse_whole_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(self: RarReader) -> Path:
        raise AssertionError("the whole archive was copied")

    monkeypatch.setattr(RarReader, "_ensure_archive_path", refuse)


def _three_streams(tmp_path: Path) -> Path:
    """A solid RAR5 of six files in three solid streams of two (``rar -s2``)."""
    src = tmp_path / "src"
    src.mkdir()
    names = []
    for i in range(6):
        (src / f"f{i}.txt").write_text(f"line {i} " * (200 + 50 * i))
        names.append(f"f{i}.txt")
    out = tmp_path / "three.rar"
    subprocess.run(
        ["rar", "a", "-s2", "-m3", "-inul", str(out), *names], cwd=src, check=True
    )
    return out


def _stream_charges(data: bytes, names: list[str]) -> list[int]:
    """The spool charge of reading each of ``names`` alone, on a fresh reader."""
    charges = []
    for name in names:
        with open_archive(BytesIO(data)) as reader:
            assert isinstance(reader, RarReader)
            reader.read(name)
            assert reader._spool is not None
            charges.append(reader._spool._written)
    return charges


# The last member of each of _three_streams's solid streams.
_STREAM_ENDS = ["f1.txt", "f3.txt", "f5.txt"]


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.parametrize("stream_source", [False, True], ids=["path", "stream"])
def test_idle_solid_streams_give_back_their_charge(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stream_source: bool
) -> None:
    """A read whose stream fits the spool limit on its own reads, whatever was read
    before: the files of streams no read holds are removed to make room."""
    path = _three_streams(tmp_path)
    data = path.read_bytes()
    expected = _pass_bytes(path)
    charges = _stream_charges(data, _STREAM_ENDS)
    if not stream_source:
        # A name the mask cannot select alone: a path source then copies too.
        monkeypatch.setattr(RarReader, "_plain_mask", lambda self, member: None)
    live = _LiveFiles(monkeypatch)
    source: object = BytesIO(data) if stream_source else path
    with open_archive(source, config=_limited(max(charges))) as reader:  # type: ignore[arg-type]
        for name in [*_STREAM_ENDS, _STREAM_ENDS[0]]:
            assert reader.read(name) == expected[name]
            assert live.live == 1
    assert live.made == 4
    assert live.live == 0


@requires_unrar_cli()
@requires_binary("rar")
def test_idle_streams_go_least_recently_read_first(tmp_path: Path) -> None:
    """A stream read again moves behind the others: the one read longest ago is
    removed first, not the one first read."""
    path = _three_streams(tmp_path)
    data = path.read_bytes()
    expected = _pass_bytes(path)
    c0, c1, c2 = _stream_charges(data, _STREAM_ENDS)
    # Any two streams fit; all three do not.
    limit = max(c0 + c1, c0 + c2, c1 + c2)
    assert limit < c0 + c1 + c2
    with open_archive(BytesIO(data), config=_limited(limit)) as reader:
        assert isinstance(reader, RarReader)
        for name in ["f1.txt", "f3.txt", "f1.txt", "f5.txt"]:
            assert reader.read(name) == expected[name]
        # The streams start at members 0, 2 and 4; f3's (2) was read longest ago.
        assert list(reader._solid_streams) == [0, 4]


@requires_unrar_cli()
@requires_binary("rar")
@pytest.mark.parametrize("stream_source", [False, True], ids=["path", "stream"])
def test_a_copy_that_cannot_fit_removes_no_idle_stream(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, stream_source: bool
) -> None:
    """Removing idle streams that cannot make room for a copy only throws their
    files away: the copy is refused, or falls back, with the streams kept."""
    path = _three_streams(tmp_path)
    data = path.read_bytes()
    c0, _, c2 = _stream_charges(data, _STREAM_ENDS)
    # f1's stream fits; f5's does not, even alone.
    assert c0 < c2
    source: object = BytesIO(data) if stream_source else path
    with open_archive(source, config=_limited(c0)) as reader:  # type: ignore[arg-type]
        assert isinstance(reader, RarReader)
        reader.read("f1.txt")
        if stream_source:
            with pytest.raises(ResourceLimitError):
                reader.read("f5.txt")
        else:
            # A plain name: the path source reads f5 in place instead.
            reader.read("f5.txt")
        assert list(reader._solid_streams) == [0]
        assert reader._solid_streams[0].file is not None


@requires_unrar_cli()
@requires_binary("rar")
def test_a_refused_budget_removes_no_idle_stream(tmp_path: Path) -> None:
    """Once the budget recorded a refusal it refuses every reservation, so
    removing idle streams cannot make room and none is removed."""
    path = _three_streams(tmp_path)
    data = path.read_bytes()
    with open_archive(BytesIO(data), config=_limited(10**6)) as reader:
        assert isinstance(reader, RarReader)
        reader.read("f1.txt")
        budget = reader._spool_budget("a test copy")
        with pytest.raises(ResourceLimitError):
            budget.check_total(10**7)
        with pytest.raises(ResourceLimitError):
            reader.read("f3.txt")
        assert list(reader._solid_streams) == [0]


@requires_unrar_cli()
@requires_binary("rar")
def test_a_held_solid_stream_keeps_its_charge(tmp_path: Path) -> None:
    """A stream file a read still holds is not removed: a copy that does not fit
    beside it is refused."""
    path = _three_streams(tmp_path)
    data = path.read_bytes()
    charges = _stream_charges(data, _STREAM_ENDS)
    with open_archive(
        BytesIO(data), config=_limited(max(charges)), concurrent_operations=True
    ) as reader:
        with reader.open(_STREAM_ENDS[0]) as held:
            with pytest.raises(ResourceLimitError):
                reader.read(_STREAM_ENDS[1])
            held.read()
        reader.read(_STREAM_ENDS[1])


@requires_unrar_cli()
@requires_binary("rar")
def test_the_stream_a_read_extends_is_not_removed(tmp_path: Path) -> None:
    """Room for a read that extends an idle stream is made from the other idle
    streams, never from the stream the read extends."""
    path = _three_streams(tmp_path)
    data = path.read_bytes()
    expected = _pass_bytes(path)
    first, last, other = _stream_charges(data, ["f0.txt", "f1.txt", "f2.txt"])
    # f0 and f2 fit together; extending f0's stream to f1 then needs f2's room.
    limit = last + other - 1
    assert first + other <= limit
    with open_archive(BytesIO(data), config=_limited(limit)) as reader:
        assert isinstance(reader, RarReader)
        for name in ["f0.txt", "f2.txt", "f1.txt"]:
            assert reader.read(name) == expected[name]
        assert list(reader._solid_streams) == [0]


class _FailingFirstFile(rs.SyntheticArchive):
    """A synthetic archive whose first temporary file cannot be made."""

    failed = False

    def __init__(self, *args: object, **kwargs: object) -> None:
        if not _FailingFirstFile.failed:
            _FailingFirstFile.failed = True
            raise OSError(28, "No space left on device")
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]


def _charged_beyond_streams(reader: RarReader) -> int:
    """Spool bytes charged to anything but the kept solid stream files."""
    assert reader._spool is not None
    kept = sum(stream.charge for stream in reader._solid_streams.values())
    return reader._spool._written - kept


@requires_unrar_cli()
def test_a_batch_file_that_cannot_be_made_gives_its_charge_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _FIXTURES / "wildcard_names__.rar"
    expected = _nonsolid_expected(path)
    monkeypatch.setattr(_FailingFirstFile, "failed", False)
    monkeypatch.setattr(rr, "SyntheticArchive", _FailingFirstFile)
    with open_archive(BytesIO(path.read_bytes())) as reader:
        assert isinstance(reader, RarReader)
        assert reader._nonsolid_pass_batches()
        got = {
            member.name: stream.read()
            for member, stream in reader.stream_members()
            if stream is not None and member.is_file
        }
        assert _FailingFirstFile.failed
        assert _charged_beyond_streams(reader) == 0
    assert got == expected


@requires_unrar_cli()
@requires_binary("rar")
def test_a_solid_run_file_that_cannot_be_made_gives_its_charge_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = _three_streams(tmp_path)
    with open_archive(path) as reader:
        assert isinstance(reader, RarReader)
        packed = [m.compress_size for m in reader._archive.members]
    # Two runs, as in test_a_solid_pass_over_a_stream_joins_small_streams_into_runs.
    monkeypatch.setattr(rr, "_pass_run_bytes", lambda limits: sum(packed[:4]))
    monkeypatch.setattr(_FailingFirstFile, "failed", False)
    monkeypatch.setattr(rr, "SyntheticArchive", _FailingFirstFile)
    with open_archive(BytesIO(path.read_bytes())) as reader:
        assert isinstance(reader, RarReader)
        with pytest.raises(OSError, match="No space left"):
            for _member, stream in reader.stream_members():
                if stream is not None:
                    stream.read()
        assert _FailingFirstFile.failed
        assert _charged_beyond_streams(reader) == 0


@requires_unrar_cli()
@pytest.mark.parametrize(
    ("fixture", "streams", "password"),
    [
        ("solid_groups__.rar", 2, None),
    ],
)
def test_a_solid_pass_over_a_stream_runs_each_stream_under_a_small_limit(
    monkeypatch: pytest.MonkeyPatch, fixture: str, streams: int, password: str | None
) -> None:
    """Under a spool limit below 128 MiB each solid stream gets one unrar run on
    its own synthetic archive, removed when its output ends; the archive is never
    copied whole."""
    path = _FIXTURES / fixture
    expected = _pass_bytes(path, password=password)
    live = _LiveFiles(monkeypatch)
    _refuse_whole_copy(monkeypatch)
    got = _pass_bytes(
        BytesIO(path.read_bytes()),
        password=password,
        config=_limited(_ONE_STREAM_PER_RUN),
    )
    assert got == expected
    assert live.made == streams
    assert live.peak == 1
    assert live.live == 0


@requires_unrar_cli()
@requires_binary("rar")
def test_a_solid_pass_over_a_stream_joins_small_streams_into_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Streams join a run while it stays within the run cap: three streams and a
    cap that holds two give two runs."""
    path = _three_streams(tmp_path)
    expected = _pass_bytes(path)
    with open_archive(path) as reader:
        assert isinstance(reader, RarReader)
        packed = [m.compress_size for m in reader._archive.members]
    cap = sum(packed[:4])
    assert cap < sum(packed)
    monkeypatch.setattr(rr, "_pass_run_bytes", lambda limits: cap)
    live = _LiveFiles(monkeypatch)
    _refuse_whole_copy(monkeypatch)
    assert _pass_bytes(BytesIO(path.read_bytes())) == expected
    assert live.made == 2
    assert live.peak == 1
    assert live.live == 0


@requires_unrar_cli()
@pytest.mark.parametrize(
    ("fixture", "password"),
    [
        ("solid_groups__.rar", None),
        ("basic_solid__.rar", None),
        ("basic_solid__rar4.rar", None),
        ("encryption_solid__.rar", "password"),
    ],
)
def test_a_solid_pass_that_would_be_one_run_copies_the_archive(
    monkeypatch: pytest.MonkeyPatch, fixture: str, password: str | None
) -> None:
    """One run would hold every packed member: it saves no disk, so the pass
    reads the whole-archive copy through one pipe instead."""
    path = _FIXTURES / fixture
    expected = _pass_bytes(path, password=password)
    live = _LiveFiles(monkeypatch)
    got = _pass_bytes(BytesIO(path.read_bytes()), password=password)
    assert got == expected
    assert live.made == 0


def test_a_failed_run_ends_the_pass_pipe() -> None:
    """A run that cannot start ends the pipe: the next run's bytes never land at
    the failed run's offsets."""
    runs = iter([b"AAAA", None, b"CCCC"])

    def next_run() -> tuple[BytesIO, object] | None:
        data = next(runs, b"")
        if data is None:
            raise ResourceLimitError("run 2 over the limit")
        if not data:
            return None
        return BytesIO(data), lambda: None

    block = SolidBlockReader(rr._SolidPassPipe(next_run))  # type: ignore[arg-type]
    assert block.open_member(0, 4).read() == b"AAAA"
    with pytest.raises(ResourceLimitError):
        block.open_member(4, 2).read()
    with pytest.raises(EOFError):
        block.open_member(6, 2).read()


@requires_unrar_cli()
def test_a_solid_pass_on_disk_reads_the_original_archive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _LiveFiles(monkeypatch)
    assert _pass_bytes(_FIXTURES / "solid_groups__.rar")
    assert live.made == 0


@requires_unrar_cli()
def test_a_solid_pass_fits_a_limit_below_the_archive() -> None:
    """Under a small limit each stream runs alone, so a limit that holds the
    larger stream but not the archive lets the pass through."""
    raw = (_FIXTURES / "solid_groups__.rar").read_bytes()
    expected = _pass_bytes(_FIXTURES / "solid_groups__.rar")
    limit = len(raw) - 1
    assert _pass_bytes(BytesIO(raw), config=_limited(limit)) == expected


@requires_unrar_cli()
def test_a_solid_pass_closed_early_removes_its_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    live = _LiveFiles(monkeypatch)
    raw = (_FIXTURES / "solid_groups__.rar").read_bytes()
    with open_archive(BytesIO(raw), config=_limited(_ONE_STREAM_PER_RUN)) as reader:
        for member, stream in reader.stream_members():
            if stream is not None and member.is_file:
                assert stream.read(1)
                break
    assert live.made == 1
    assert live.live == 0


def test_a_stream_pass_charges_each_member_its_own_run() -> None:
    """One stream per run: a member pays for its solid chain alone. One run over
    both streams: the whole archive's walk, as unrar keeps the window across."""
    raw = (_FIXTURES / "solid_groups__.rar").read_bytes()
    with open_archive(BytesIO(raw), config=_limited(_ONE_STREAM_PER_RUN)) as reader:
        assert isinstance(reader, RarReader)
        members = reader._archive.members
        runs = reader._solid_pass_run_plan()
        assert runs is not None and len(runs) == 2
        costs = reader._stream_pass_costs(runs)
        last = reader._members[-1]
        assert costs[id(last)].declarer >= runs[1].start > 0
        for index, member in enumerate(reader._members):
            chain = rs.solid_chain(members, index)
            assert costs[id(member)] == rr._chain_dictionary_cost(members, chain)
    with open_archive(BytesIO(raw)) as reader:
        assert isinstance(reader, RarReader)
        assert reader._solid_pass_run_plan() is None
        packed = [
            i
            for i, info in enumerate(reader._archive.members)
            if rs.has_packed_data(info)
        ]
        one = [rr._PassRun(0, packed, 0)]
        assert reader._stream_pass_costs(one) == reader._pass_dictionary_costs()


# ------------------------------------------------------------- nonsolid batches


class _Spawns:
    """The synthetic archives ``unrar`` is started on, with their member counts."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[Path] = []
        real = rr.open_unrar_p

        def spawn(path: Path, *args: object, **kwargs: object) -> object:
            self.calls.append(Path(path))
            return real(path, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(rr, "open_unrar_p", spawn)


_BATCHED = ["wildcard_names__.rar", "wildcard_names__rar4.rar"]


def _nonsolid_expected(path: Path) -> dict[str, bytes]:
    with open_archive(path) as reader:
        return {m.name: reader.read(m) for m in reader.members() if m.is_file}


@requires_unrar_cli()
@pytest.mark.parametrize("fixture", _BATCHED)
@pytest.mark.parametrize("stream_source", [False, True], ids=["path", "stream"])
def test_a_nonsolid_pass_reads_a_batch_with_one_unrar(
    monkeypatch: pytest.MonkeyPatch, fixture: str, stream_source: bool
) -> None:
    """The six compressed members share one synthetic archive and one ``unrar``;
    the stored one is read by archivey. The run's file is gone after the pass."""
    path = _FIXTURES / fixture
    expected = _nonsolid_expected(path)
    spawns = _Spawns(monkeypatch)
    live = _LiveFiles(monkeypatch)
    source: object = BytesIO(path.read_bytes()) if stream_source else path
    assert _pass_bytes(source) == expected
    assert len(spawns.calls) == 1
    assert live.made == 1
    assert live.live == 0


@requires_unrar_cli()
@pytest.mark.parametrize("fixture", _BATCHED)
def test_a_nonsolid_pass_that_skips_members_still_reads_the_rest(
    monkeypatch: pytest.MonkeyPatch, fixture: str
) -> None:
    path = _FIXTURES / fixture
    expected = _nonsolid_expected(path)
    spawns = _Spawns(monkeypatch)
    with open_archive(path) as reader:
        names = [m.name for m in reader.members() if m.is_file]
        wanted = {names[-1], names[2]}
        got = {
            member.name: stream.read()
            for member, stream in reader.stream_members()
            if stream is not None and member.name in wanted
        }
    assert got == {name: expected[name] for name in wanted}
    assert len(spawns.calls) == 1


@requires_unrar_cli()
@pytest.mark.parametrize("fixture", _BATCHED)
def test_a_batch_that_stops_lining_up_reads_the_rest_on_their_own(
    monkeypatch: pytest.MonkeyPatch, fixture: str
) -> None:
    """A member whose output does not match its CRC32 marks the batch: the
    members after it are read one at a time, and every read is still right."""
    path = _FIXTURES / fixture
    expected = _nonsolid_expected(path)
    real = RarReader._nonsolid_pass_batches

    def misplanned(self: RarReader) -> list[rr._NonsolidBatch]:
        batches = real(self)
        batches[0].crcs[1] ^= 1
        return batches

    monkeypatch.setattr(RarReader, "_nonsolid_pass_batches", misplanned)
    spawns = _Spawns(monkeypatch)
    assert _pass_bytes(path) == expected
    with open_archive(path) as reader:
        assert isinstance(reader, RarReader)
        (batch,) = real(reader)
    # The batch's run, then one read each for the members after position 1.
    assert len(spawns.calls) == 1 + len(batch.indices) - 2


@requires_unrar_cli()
def test_a_batch_over_the_spool_limit_reads_each_member_on_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _FIXTURES / "wildcard_names__.rar"
    expected = _nonsolid_expected(path)
    with open_archive(path) as reader:
        assert isinstance(reader, RarReader)
        (batch,) = reader._nonsolid_pass_batches()
        largest = max(reader._archive.members[i].compress_size for i in batch.indices)
    spawns = _Spawns(monkeypatch)
    # Room for any one member's copy, not for the batch's.
    limit = rs.SyntheticArchive.overhead(5) + largest + 200
    assert limit < batch.packed
    got = _pass_bytes(BytesIO(path.read_bytes()), config=_limited(limit))
    assert got == expected
    assert len(spawns.calls) == len(batch.indices)


def _checked(output: bytes | None, sizes: list[int], crcs: list[int]) -> tuple:
    batch = rr._NonsolidBatch([0] * len(sizes), sizes, crcs, 0)
    run = rr._CheckedRun(None if output is None else BytesIO(output), batch)
    data = b""
    while chunk := run.read(3):
        data += chunk
    run.close()
    return data, batch.tainted


def test_a_checked_run_holds_the_output_to_the_plan() -> None:
    a, b = b"hello", b"world!"
    crcs = [zlib.crc32(a), zlib.crc32(b)]
    assert _checked(a + b, [5, 6], crcs) == (a + b, None)
    # Output past the last member: the read that completes it raises.
    with pytest.raises(CorruptionError, match="exceeds its declared size of 6"):
        _checked(a + b + b"tail", [5, 6], crcs)
    # One byte short in the first member: it fails its CRC32, the second reads
    # short, and nothing is made up.
    data, tainted = _checked(a[:4] + b, [5, 6], crcs)
    assert data == a[:4] + b[:6] and len(data) == 10 and tainted == 0
    # Ends early: short, marked where it ended.
    assert _checked(a, [5, 6], crcs) == (a, 1)
    # No run at all.
    assert _checked(None, [5, 6], crcs) == (b"", 0)
    # An empty member checks at once.
    assert _checked(a, [0, 5], [0, zlib.crc32(a)]) == (a, None)


def test_a_member_whose_run_ends_early_reads_short() -> None:
    """The member being read when the run ends sees the real end, so its own
    size check raises, even when its CRC32 matches zero-padded bytes."""
    a, b = b"hello", b"world!"
    padded = b[:2] + bytes(4)
    batch = rr._NonsolidBatch([0, 1], [5, 6], [zlib.crc32(a), zlib.crc32(padded)], 0)
    block = SolidBlockReader(rr._CheckedRun(BytesIO(a + b[:2]), batch))
    view = block.open_member(5, 6)
    assert view.read() == b[:2]
    assert view.read() == b""
    assert batch.tainted == 1
    block.close()


# Small enough that wildcard_names__.rar's six compressed members (47-50 packed
# bytes each) make three batches of two: [0, 2], [3, 4] and [5, 6].
_THREE_BATCHES = 101


@requires_unrar_cli()
@pytest.mark.parametrize("stream_source", [False, True], ids=["path", "stream"])
def test_a_nonsolid_pass_reads_several_batches(
    monkeypatch: pytest.MonkeyPatch, stream_source: bool
) -> None:
    path = _FIXTURES / "wildcard_names__.rar"
    expected = _nonsolid_expected(path)
    monkeypatch.setattr(rr, "_SYNTHETIC_IN_PLACE_THRESHOLD", _THREE_BATCHES)
    with open_archive(path) as reader:
        assert isinstance(reader, RarReader)
        assert [b.indices for b in reader._nonsolid_pass_batches()] == [
            [0, 2],
            [3, 4],
            [5, 6],
        ]
    spawns = _Spawns(monkeypatch)
    live = _LiveFiles(monkeypatch)
    source: object = BytesIO(path.read_bytes()) if stream_source else path
    assert _pass_bytes(source) == expected
    assert len(spawns.calls) == 3
    assert live.live == 0


@requires_unrar_cli()
def test_a_batch_whose_members_are_all_skipped_runs_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _FIXTURES / "wildcard_names__.rar"
    expected = _nonsolid_expected(path)
    monkeypatch.setattr(rr, "_SYNTHETIC_IN_PLACE_THRESHOLD", _THREE_BATCHES)
    spawns = _Spawns(monkeypatch)
    with open_archive(path) as reader:
        last = reader._members[-1].name  # type: ignore[attr-defined]
        got = {
            member.name: stream.read()
            for member, stream in reader.stream_members()
            if stream is not None and member.name == last
        }
    assert got == {last: expected[last]}
    assert len(spawns.calls) == 1


@requires_unrar_cli()
def test_a_tainted_batch_leaves_the_next_batch_on_its_own_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = _FIXTURES / "wildcard_names__.rar"
    expected = _nonsolid_expected(path)
    monkeypatch.setattr(rr, "_SYNTHETIC_IN_PLACE_THRESHOLD", _THREE_BATCHES)
    real = RarReader._nonsolid_pass_batches

    def misplanned(self: RarReader) -> list[rr._NonsolidBatch]:
        batches = real(self)
        batches[0].crcs[0] ^= 1
        return batches

    monkeypatch.setattr(RarReader, "_nonsolid_pass_batches", misplanned)
    spawns = _Spawns(monkeypatch)
    assert _pass_bytes(path) == expected
    # Three runs, and member 2 read on its own after batch 0 stopped lining up.
    assert len(spawns.calls) == 4


@requires_unrar_cli()
def test_a_member_over_the_dictionary_limit_is_left_out_of_batches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``unrar`` decodes a batch past the member read, so a member whose
    dictionary is over the limit is never in a batch: it is refused alone, and
    the rest of the pass still reads."""
    path = _FIXTURES / "wildcard_names__.rar"
    expected = _nonsolid_expected(path)
    monkeypatch.setattr(rr, "_SYNTHETIC_IN_PLACE_THRESHOLD", _THREE_BATCHES)
    config = ArchiveyConfig(decoder_limits=DecoderLimits(max_decoder_memory=8203))
    with open_archive(path, config=config) as reader:
        assert isinstance(reader, RarReader)
        over = [
            index
            for index, member in enumerate(reader._members)
            if reader._dictionary_costs[id(member)].count > 8203
        ]
        assert over == [2]
        batches = reader._nonsolid_pass_batches()
        assert batches and all(2 not in b.indices for b in batches)
        got: dict[str, bytes] = {}
        for member, stream in reader.stream_members():
            if stream is None:
                continue
            if member is reader._members[2]:
                with pytest.raises(ResourceLimitError):
                    stream.read()
                continue
            got[member.name] = stream.read()
    assert got == {k: v for k, v in expected.items() if k != "a*.txt"}
