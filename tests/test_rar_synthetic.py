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

from archivey import ArchiveyConfig, SpoolLimits, open_archive
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
from tests.conftest import requires, requires_unrar_cli

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
        assert reader._solid_streams[0].file is None


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


@requires_unrar_cli()
@pytest.mark.parametrize("per_stream", [False, True], ids=["batched", "per_stream"])
@pytest.mark.parametrize(
    ("fixture", "streams", "password"),
    [
        ("solid_groups__.rar", 2, None),
        ("basic_solid__.rar", 1, None),
        ("basic_solid__rar4.rar", 1, None),
        ("encryption_solid__.rar", 1, "password"),
    ],
)
def test_a_solid_pass_over_a_stream_reads_one_run_at_a_time(
    monkeypatch: pytest.MonkeyPatch,
    fixture: str,
    streams: int,
    password: str | None,
    per_stream: bool,
) -> None:
    """Each run of solid streams gets one unrar run on its own synthetic archive,
    removed when its output ends; the archive is never copied whole. Small streams
    share a run; under a small spool limit each stream runs alone."""
    path = _FIXTURES / fixture
    expected = _pass_bytes(path, password=password)
    live = _LiveFiles(monkeypatch)

    def refuse(self: RarReader) -> Path:
        raise AssertionError("the whole archive was copied")

    monkeypatch.setattr(RarReader, "_ensure_archive_path", refuse)
    kwargs: dict[str, object] = {"password": password}
    if per_stream:
        kwargs["config"] = _limited(_ONE_STREAM_PER_RUN)
    got = _pass_bytes(BytesIO(path.read_bytes()), **kwargs)
    assert got == expected
    assert live.made == (streams if per_stream else 1)
    assert live.peak == 1
    assert live.live == 0


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
    with open_archive(BytesIO(raw)) as reader:
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
        runs = reader._solid_pass_groups()
        assert runs is not None and len(runs) == 2
        costs = reader._stream_pass_costs(runs)
        last = reader._members[-1]
        assert costs[id(last)].declarer >= runs[1].start > 0
        for index, member in enumerate(reader._members):
            chain = rs.solid_chain(members, index)
            assert costs[id(member)] == rr._chain_dictionary_cost(members, chain)
    with open_archive(BytesIO(raw)) as reader:
        assert isinstance(reader, RarReader)
        runs = reader._solid_pass_groups()
        assert runs is not None and len(runs) == 1
        assert reader._stream_pass_costs(runs) == reader._pass_dictionary_costs()
