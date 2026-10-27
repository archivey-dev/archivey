"""A ZIP read from a source that cannot seek, through its local headers.

The reader (``zip_forward_reader``) walks the local headers, yields each member with
what its header says, and updates the members in place from the central directory at
the end of the pass.
"""

from __future__ import annotations

import bz2
import dataclasses
import io
import random
import struct
import zipfile
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import archivey
from archivey.config import ListingLimits
from archivey.cost import AccessCost, ListingCost, StreamCapability
from archivey.diagnostics import (
    DiagnosticCode,
    DiagnosticPolicy,
    SymlinkTargetContext,
    UnlistedDataContext,
)
from archivey.exceptions import (
    CorruptionError,
    DiagnosticRaisedError,
    EncryptionError,
    LinkTargetNotFoundError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import zip_forward_reader, zip_local_walk
from archivey.internal.backends.zip_forward_reader import (
    _MAX_REPARSE_PREFIX,
    ZipForwardReader,
)
from archivey.internal.base_reader import MAX_LINK_TARGET_BYTES
from archivey.types import ArchiveMember, ExtractionStatus, MemberType
from tests.conftest import importorskip
from tests.memory_util import traced_peak
from tests.sample_archives import (
    CORPUS,
    CorpusEntry,
    build_archive,
    skip_unless_runnable,
)
from tests.streams_util import NonSeekableBytesIO, ShortReadNonSeekable
from tests.zip_descriptors import without_descriptor_signatures
from tests.zipcrypto import build_stored_zipcrypto_zip


class _Writer(io.RawIOBase):
    """A pipe to write into: stdlib ``zipfile`` then sets bit 3 on every member."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def write(self, b: bytes | bytearray | memoryview) -> int:  # type: ignore[override]
        self.data += b
        return len(b)


def _streamed(data: bytes) -> bytes:
    """``data``'s members written again to a pipe: bit 3 and a descriptor on each."""
    out = _Writer()
    with zipfile.ZipFile(io.BytesIO(data)) as src, zipfile.ZipFile(out, "w") as dst:
        dst.comment = src.comment
        for info in src.infolist():
            dst.writestr(info, src.read(info), compress_type=info.compress_type)
    with zipfile.ZipFile(io.BytesIO(out.data)) as written:
        assert all(info.flag_bits & 0x08 for info in written.infolist())
    return bytes(out.data)


def _zip(entries: list[tuple[str, bytes]], *, method: int = zipfile.ZIP_DEFLATED,
         comment: bytes = b"") -> bytes:  # fmt: skip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        zf.comment = comment
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


def _symlink_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", b"hello")
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        zf.writestr(info, b"a.txt")
    return buf.getvalue()


def _symlink_zip_stored() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("a.txt", b"hello")
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        zf.writestr(info, b"a.txt")
    return buf.getvalue()


def _pipe(data: bytes) -> NonSeekableBytesIO:
    return NonSeekableBytesIO(data)


def _visible(member: ArchiveMember) -> dict[str, object]:
    """A member's public fields and the codes of what it reported."""
    out = {
        f.name: getattr(member, f.name)
        for f in dataclasses.fields(member)
        if not f.name.startswith("_") and f.name not in ("link_target_member", "extra")
    }
    out["extra"] = dict(member.extra)
    out["diagnostics"] = sorted(str(d.code) for d in member._diagnostics)  # type: ignore[attr-defined]
    return out


def _seekable_view(
    data: bytes, *, read: bool = True
) -> tuple[list[dict[str, object]], dict[int, bytes]]:
    """The members a file read lists, and each file's contents unless ``read`` is
    false: for a crafted archive whose member data overlaps its own records."""
    with archivey.open_archive(io.BytesIO(data)) as reader:
        members = reader.members()
        contents = {
            m._member_id: reader.read(m)  # type: ignore[misc]
            for m in members
            if m.is_file and read
        }
        return [_visible(m) for m in members], contents


def _piped_view(
    data: bytes, source: object = None
) -> tuple[list[dict[str, object]], dict[int, bytes]]:
    yielded: list[tuple[ArchiveMember, bytes | None]] = []
    stream = source if source is not None else _pipe(data)
    with archivey.open_archive(stream, streaming=True) as reader:  # type: ignore[arg-type]
        for member, data_stream in reader.stream_members():
            yielded.append(
                (member, data_stream.read() if data_stream is not None else None)
            )
        listed = list(reader.members_report().members)
    assert [m for m, _ in yielded] == listed
    contents = {m._member_id: d for m, d in yielded if m.is_file and d is not None}  # type: ignore[misc]
    return [_visible(m) for m in listed], contents


def _corpus_zips() -> Iterator[pytest.ParameterSet]:
    for entry in CORPUS:
        if "zip" in entry.formats and not entry.passwords:
            yield pytest.param(entry, id=entry.id)


@pytest.mark.filterwarnings("ignore:Duplicate name")
@pytest.mark.parametrize("entry", list(_corpus_zips()))
@pytest.mark.parametrize("written", ["sized", "streamed"])
def test_a_pipe_lists_the_corpus_as_the_seekable_read_does(
    entry: CorpusEntry, written: str, tmp_path: Path
) -> None:
    """Same members, fields, diagnostics and contents after the pass as from a file.

    ``streamed`` writes every member with bit 3 and a data descriptor, as stdlib
    ``zipfile`` does to a pipe."""
    skip_unless_runnable(entry, "zip")
    path = tmp_path / "corpus.zip"
    build_archive(entry, "zip", path)
    data = path.read_bytes()
    if written == "streamed":
        data = _streamed(data)
    assert _piped_view(data) == _seekable_view(data)


def test_short_reads_from_the_pipe_change_nothing() -> None:
    data = _streamed(_zip([("a.txt", b"x" * 70_000), ("b.txt", b"hello")]))
    assert _piped_view(data, ShortReadNonSeekable(data, 7)) == _seekable_view(data)


def test_members_change_until_the_directory_is_read() -> None:
    """A member is typed from its local header, so ``member_state_final`` is false
    until the end of the pass, which updates it from the directory."""
    data = _symlink_zip()
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        seen = []
        for member, _stream in reader.stream_members():
            assert member.member_state_final is False
            assert member.mode is None
            assert member.create_system is None
            seen.append((member.name, member.type))
        assert seen == [("a.txt", MemberType.FILE), ("link", MemberType.FILE)]
        link = reader.members_report().members[1]
    assert link.type is MemberType.SYMLINK
    assert link.link_target == "a.txt"
    assert link.mode == 0o777
    assert link.member_state_final is True


def test_a_link_whose_data_the_caller_read_keeps_its_target() -> None:
    data = _streamed(_symlink_zip())
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            stream.read()
        link = reader.members_report().members[1]
    assert (link.type, link.link_target) == (MemberType.SYMLINK, "a.txt")


def test_what_the_caller_sees_before_and_after_the_directory() -> None:
    data = _zip([("a.txt", b"one"), ("b.txt", b"two")], comment=b"hi")
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        info = reader.info
        assert (info.member_count, info.comment) == (None, None)
        assert info.cost.listing_cost is ListingCost.REQUIRES_SCANNING
        assert info.cost.access_cost is AccessCost.DIRECT
        assert info.cost.stream_capability is StreamCapability.FORWARD_ONLY
        assert reader.members_report_if_available() is None
        for _ in reader.stream_members():
            pass
        assert (reader.info.member_count, reader.info.comment) == (2, "hi")
        assert reader.members_report_if_available() is not None


def test_a_stream_reads_nothing_once_the_walk_has_moved_on() -> None:
    data = _zip([("a.txt", b"one"), ("b.txt", b"two")])
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        passes = reader.stream_members()
        _member, first = next(passes)
        assert first is not None
        next(passes)
        with pytest.raises(ValueError, match="closed"):
            first.read()


def _corrupt_stored(data: bytes, payload: bytes) -> bytes:
    at = data.index(payload)
    return data[:at] + bytes([payload[0] ^ 0xFF]) + data[at + 1 :]


def _corrupt_data(data: bytes, method: int) -> bytes:
    """``data`` with the middle of its first member's data overwritten."""
    if method == zipfile.ZIP_STORED:
        return _corrupt_stored(data, b"payload bytes " * 100)
    name_len, extra_len = struct.unpack_from("<HH", data, 26)
    (size,) = struct.unpack_from("<I", data, 18)
    at = 30 + name_len + extra_len + size // 2
    return data[:at] + b"\xff" * 8 + data[at + 8 :]


@pytest.mark.parametrize(
    "method",
    [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA],
)
def test_a_damaged_member_fails_when_read_and_not_when_skipped(method: int) -> None:
    """Short enough to be a link target, the skipped member is decoded anyway (its
    bytes would be the target); that decode failing costs only those bytes."""
    payload = b"payload bytes " * 100
    data = _zip([("bad.bin", payload), ("ok.txt", b"fine")], method=method)
    data = _corrupt_data(data, method)
    with (
        archivey.open_archive(io.BytesIO(data)) as reader,
        pytest.raises(CorruptionError),
    ):
        reader.read(reader.get("bad.bin"))
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        for member, stream in reader.stream_members():
            if member.name == "bad.bin":
                assert stream is not None
                with pytest.raises(CorruptionError):
                    stream.read()
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        names = [
            m.name for m, _ in reader.stream_members(lambda m: m.name != "bad.bin")
        ]
    assert names == ["ok.txt"]


_DAMAGED_PAYLOAD = b"payload bytes " * 100
_AFTER_DAMAGE = [("b.txt", b"fine"), ("c.txt", b"also fine")]


def _with_damaged_descriptor(method: int, *, signed: bool, field: str) -> bytes:
    """A bit-3 ``bad.bin`` with one byte of ``field`` flipped, then two members.

    ``field`` is ``"data"`` (a byte in the middle of a STORED member's data), or
    ``"signature"``, ``"crc"``, ``"csize"`` or ``"usize"`` of its data descriptor.
    """
    data = _streamed(
        _zip([("bad.bin", _DAMAGED_PAYLOAD), *_AFTER_DAMAGE], method=method)
    )
    if not signed:
        data = without_descriptor_signatures(data)
    out = bytearray(data)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        info = zf.getinfo("bad.bin")
    name_len, extra_len = struct.unpack_from("<HH", out, 26)
    start = 30 + name_len + extra_len
    if field == "data":
        # Damaged DEFLATE data fails its decode instead, which another test covers.
        assert method == zipfile.ZIP_STORED
        out[start + len(_DAMAGED_PAYLOAD) // 2] ^= 0x01
        return bytes(out)
    descriptor = start + info.compress_size
    body = descriptor + 4 if signed else descriptor
    at = {
        "signature": descriptor + 2,
        "crc": body,
        "csize": body + 4,
        "usize": body + 8,
    }
    out[at[field]] ^= 0x01
    return bytes(out)


_DAMAGED_DESCRIPTORS = [
    pytest.param(method, signed, field, id=f"{label}-{shape}-{field}")
    for method, label in (
        (zipfile.ZIP_STORED, "stored"), (zipfile.ZIP_DEFLATED, "deflated")
    )
    for signed, shape in ((True, "signed"), (False, "unsigned"))
    for field in ("data", "signature", "crc", "csize", "usize")
    if not (field == "signature" and not signed)
    # A damaged DEFLATE stream fails its decode: the scan after a failed decode
    # covers that (``test_a_damaged_member_fails_when_read_and_not_when_skipped``).
    and not (field == "data" and method != zipfile.ZIP_STORED)
]  # fmt: skip


@pytest.mark.parametrize(("method", "signed", "field"), _DAMAGED_DESCRIPTORS)
def test_one_damaged_byte_in_a_bit3_member_fails_it_alone(
    method: int, signed: bool, field: str
) -> None:
    """The walk finds where the damaged member ends by its descriptor with one field
    damaged (DR-2), and reads every member after it. The member fails when its read
    checks the descriptor, or at the end of the pass when the directory does; one the
    file read reads cleanly (a damaged signature) reads cleanly here too."""
    data = _with_damaged_descriptor(method, signed=signed, field=field)
    with archivey.open_archive(io.BytesIO(data)) as reader:
        file_ok = True
        try:
            reader.read(reader.get("bad.bin"))
        except CorruptionError:
            file_ok = False
    read: dict[str, bytes | type[Exception]] = {}
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        pass_ = reader.stream_members()
        failed_at_end = False
        while True:
            try:
                member, stream = next(pass_)
            except StopIteration:
                break
            except CorruptionError as exc:
                assert "differs from its central" in str(exc)
                failed_at_end = True
                break
            assert stream is not None
            try:
                read[member.name] = stream.read()
            except CorruptionError as exc:
                read[member.name] = type(exc)
    assert {k: v for k, v in read.items() if k != "bad.bin"} == dict(_AFTER_DAMAGE)
    if field in ("data", "signature"):
        # The descriptor agrees with the directory.
        assert not failed_at_end
        assert (read["bad.bin"] == _DAMAGED_PAYLOAD) == file_ok
    else:
        assert failed_at_end
    if field == "csize":
        # The data and its CRC are intact; the directory catches the size.
        assert read["bad.bin"] == _DAMAGED_PAYLOAD
    elif field != "signature":
        assert issubclass(read["bad.bin"], CorruptionError)  # type: ignore[arg-type]


@pytest.mark.parametrize(("method", "signed", "field"), _DAMAGED_DESCRIPTORS)
def test_a_damaged_bit3_member_nobody_reads_does_not_end_the_pass(
    method: int, signed: bool, field: str
) -> None:
    data = _with_damaged_descriptor(method, signed=signed, field=field)
    names = []
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        try:
            for member, _stream in reader.stream_members():
                names.append(member.name)
        except CorruptionError as exc:
            assert "differs from its central" in str(exc)
    assert names == ["bad.bin", "b.txt", "c.txt"]


def test_a_bit3_stored_member_with_two_damaged_descriptor_fields_ends_the_pass() -> (
    None
):
    """With its CRC and both sizes off, nothing places the descriptor: the scan reads
    to the end record and the pass ends there."""
    data = bytearray(
        _with_damaged_descriptor(zipfile.ZIP_STORED, signed=True, field="csize")
    )
    with zipfile.ZipFile(io.BytesIO(bytes(data))) as zf:
        info = zf.getinfo("bad.bin")
    usize = 30 + len("bad.bin") + info.compress_size + 4 + 8
    data[usize] ^= 0x01
    with (
        archivey.open_archive(_pipe(bytes(data)), streaming=True) as reader,
        pytest.raises(UnsupportedFeatureError, match="data descriptor"),
    ):
        for _ in reader.stream_members():
            pass


def test_a_deflated_member_whose_descriptor_crc_differs_fails_when_read() -> None:
    data = bytearray(_streamed(_zip([("a.txt", b"hello world " * 50)])))
    # The descriptor sits right after the data: PK\x07\x08, then the CRC.
    at = data.index(b"PK\x07\x08") + 4
    data[at] ^= 0x01
    with archivey.open_archive(_pipe(bytes(data)), streaming=True) as reader:
        pass_ = reader.stream_members()
        _member, stream = next(pass_)
        assert stream is not None
        with pytest.raises(CorruptionError, match="CRC"):
            stream.read()
        # The directory then contradicts the descriptor, as the end of the pass finds.
        with pytest.raises(CorruptionError, match="data descriptor after its data"):
            next(pass_)


def _drop_local_member(data: bytes, name: bytes) -> bytes:
    """``data`` with the central entry for ``name`` pointed at a missing local header."""
    out = bytearray(data)
    cd = out.index(b"PK\x01\x02" + b"\x14", 0)
    while cd >= 0:
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", out, cd + 28)
        if bytes(out[cd + 46 : cd + 46 + name_len]) == name:
            struct.pack_into("<I", out, cd + 42, 999_999)
            return bytes(out)
        cd = out.find(b"PK\x01\x02", cd + 46 + name_len + extra_len + comment_len)
    raise AssertionError(name)


def test_a_damaged_link_target_is_reported_as_damaged() -> None:
    data = _zip(
        [("link", b"payload bytes " * 100), ("ok.txt", b"fine")],
        method=zipfile.ZIP_DEFLATED,
    )
    data = bytearray(_corrupt_data(data, zipfile.ZIP_DEFLATED))
    cd = data.index(b"PK\x01\x02")
    data[cd + 5] = 3  # made on Unix
    struct.pack_into("<I", data, cd + 38, 0o120777 << 16)  # a symlink's mode
    with archivey.open_archive(_pipe(bytes(data)), streaming=True) as reader:
        reader.members_report()
        assert _link_target_reasons(reader) == ["target_data_damaged"]


def _link_target_reasons(reader: archivey.ArchiveReader) -> list[str]:
    return [
        d.context.reason
        for d in reader.diagnostics.retained
        if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        and isinstance(d.context, SymlinkTargetContext)
    ]


def test_an_encrypted_link_target_needs_a_password_as_from_a_file() -> None:
    data = bytearray(_symlink_zip_stored())
    data[data.index(b"PK\x03\x04", 1) + 6] |= 0x01
    cd = data.index(b"PK\x01\x02", data.index(b"PK\x01\x02") + 1)
    data[cd + 8] |= 0x01

    for source, streaming in ((_pipe(bytes(data)), True), (io.BytesIO(data), False)):
        with archivey.open_archive(source, streaming=streaming) as reader:
            reader.members_report()
            assert _link_target_reasons(reader) == ["password_required"]


def test_an_encrypted_bit3_compressed_member_is_passed_without_its_password() -> None:
    """Nobody asked for it, so the scan finds its end on the bytes as stored, and
    the pass needs no key to go past it."""
    data = bytearray(_streamed(_zip([("a.txt", b"one" * 50), ("b.txt", b"two")])))
    data[6] |= 0x01
    data[data.index(b"PK\x01\x02") + 8] |= 0x01
    with archivey.open_archive(_pipe(bytes(data)), streaming=True) as reader:
        read = [
            (member.name, stream.read())
            for member, stream in reader.stream_members(lambda m: m.name == "b.txt")
            if stream is not None
        ]
    assert read == [("b.txt", b"two")]


def _repeat_directory(data: bytes, times: int) -> bytes:
    """``data`` (one member) with its one central entry repeated ``times`` times."""
    cd = data.index(b"PK\x01\x02")
    eocd = data.index(b"PK\x05\x06")
    entry = data[cd:eocd]
    end = bytearray(data[eocd:])
    struct.pack_into("<HHI", end, 8, times, times, len(entry) * times)
    return data[:cd] + entry * times + bytes(end)


@pytest.mark.parametrize("source", ["pipe", "file"])
def test_max_members_counts_the_directory_entries(source: str) -> None:
    data = _repeat_directory(_zip([("a.txt", b"one")], method=zipfile.ZIP_STORED), 50)
    config = archivey.ArchiveyConfig(listing_limits=ListingLimits(max_members=10))
    opened = _pipe(data) if source == "pipe" else io.BytesIO(data)
    with (
        pytest.raises(ResourceLimitError, match="max_members=10"),
        archivey.open_archive(opened, streaming=True, config=config) as reader,
    ):
        for _ in reader.stream_members():
            pass


def test_two_entries_for_one_local_header_are_named_as_such() -> None:
    data = _repeat_directory(_zip([("a.txt", b"one")], method=zipfile.ZIP_STORED), 2)
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        report = reader.members_report()
    assert isinstance(report.error, CorruptionError)
    assert "an earlier entry already describes" in str(report.error)


def test_directory_comments_count_toward_max_metadata_bytes() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(20):
            info = zipfile.ZipInfo(f"{i}.txt")
            info.comment = b"c" * 6000
            zf.writestr(info, b"x")
    data = buf.getvalue()
    config = archivey.ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=100_000)
    )
    with (
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
        archivey.open_archive(io.BytesIO(data), config=config) as reader,
    ):
        reader.members()
    with (
        archivey.open_archive(_pipe(data), streaming=True, config=config) as reader,
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
    ):
        reader.members_report()


def _small_files_then_link(count: int, size: int, target: str) -> bytes:
    """``count`` files of ``size`` bytes each, all short enough to be link targets,
    then a symlink to ``target``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(count):
            zf.writestr(f"f{i:03d}.txt", (b"%03d" % i) * (size // 3))
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        zf.writestr(info, target.encode())
    return buf.getvalue()


def _limited(max_metadata_bytes: int) -> archivey.ArchiveyConfig:
    return archivey.ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=max_metadata_bytes)
    )


@pytest.mark.parametrize("written", ["sized", "streamed"])
def test_small_files_data_is_not_charged_to_max_metadata_bytes(written: str) -> None:
    """Every member short enough to be a link keeps its data until the directory
    says which are links. That data is not listing metadata: a file read keeps none
    of it, so an archive of many small files lists from a pipe as from a file, and
    the link after them keeps its target."""
    data = _small_files_then_link(40, 3000, "f000.txt")
    if written == "streamed":
        data = _streamed(data)
    config = _limited(20_000)
    with archivey.open_archive(io.BytesIO(data), config=config) as reader:
        from_file = [(m.name, m.link_target) for m in reader.members()]
    with archivey.open_archive(_pipe(data), streaming=True, config=config) as reader:
        read = {m.name: s.read() for m, s in reader.stream_members() if s is not None}
        from_pipe = [(m.name, m.link_target) for m in reader.members_report().members]
    assert from_pipe == from_file
    assert from_pipe[-1] == ("link", "f000.txt")
    assert read["f039.txt"] == b"039" * 1000


def test_kept_ciphertext_is_not_charged_to_max_metadata_bytes() -> None:
    """Short encrypted members nobody read keep their ciphertext for a link target,
    under the same bound as plain data, not the listing's."""
    data = build_stored_zipcrypto_zip(
        [(b"pw", f"f{i:03d}.bin".encode(), bytes([i]) * 3000) for i in range(40)]
    )
    with archivey.open_archive(
        _pipe(data), streaming=True, config=_limited(20_000)
    ) as reader:
        for _ in reader.stream_members():
            pass
        assert len(reader.members_report().members) == 40


def test_the_kept_data_drops_the_longest_first() -> None:
    """The pass holds at most ``max_metadata_bytes`` of short members' data, and drops
    the longest first: link targets are paths, shorter than most files. Only a target
    at least as long as the ``max_metadata_bytes`` of data before it is lost so; the
    link is then listed without it and says why, and the rest of the listing stands,
    where the file read lists the target."""
    short = _small_files_then_link(10, 3000, "f000.txt")
    with archivey.open_archive(
        _pipe(short), streaming=True, config=_limited(20_000)
    ) as reader:
        for _ in reader.stream_members():
            pass
        assert reader.members_report().members[-1].link_target == "f000.txt"
    target = "d/" * 1750
    long = _small_files_then_link(10, 3000, target)
    with archivey.open_archive(io.BytesIO(long), config=_limited(20_000)) as reader:
        assert reader.members()[-1].link_target == target
    with archivey.open_archive(
        _pipe(long), streaming=True, config=_limited(20_000)
    ) as reader:
        for _ in reader.stream_members():
            pass
        members = reader.members_report().members
        assert len(members) == 11
        link = members[-1]
        assert (link.name, link.type, link.link_target) == (
            "link",
            MemberType.SYMLINK,
            None,
        )
        assert _link_target_reasons(reader) == ["target_data_dropped"]
        (message,) = [
            d.message
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
        assert "max_metadata_bytes=20000" in message


def test_a_link_whose_kept_data_was_dropped_leaves_no_file_behind(
    tmp_path: Path,
) -> None:
    """The pass stages the link's data as a file's before the directory makes it a
    link. With the target dropped, placement does not place the link and fails it
    alone, as for any link whose target the read cannot reach."""
    data = _small_files_then_link(10, 3000, "d/" * 1750)
    with archivey.open_archive(
        _pipe(data), streaming=True, config=_limited(20_000)
    ) as reader:
        report = reader.extract_all(tmp_path, on_error="continue")
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        f"f{i:03d}.txt" for i in range(10)
    ]
    assert (tmp_path / "f009.txt").read_bytes() == b"009" * 1000
    (link,) = [r for r in report.results if r.member.name == "link"]
    assert link.status is ExtractionStatus.FAILED
    assert isinstance(link.error, LinkTargetNotFoundError)
    assert link.path is None


@pytest.mark.parametrize("source", ["pipe", "file"])
def test_the_archive_comment_counts_toward_max_metadata_bytes(source: str) -> None:
    """A file read weighs the comment before the first member; the pass weighs it
    once it reaches the end record."""
    data = _zip([("a.txt", b"one")], comment=b"c" * 65_000)
    opened = _pipe(data) if source == "pipe" else io.BytesIO(data)
    with (
        archivey.open_archive(opened, streaming=True, config=_limited(1000)) as reader,
        pytest.raises(ResourceLimitError, match="max_metadata_bytes"),
    ):
        for _ in reader.stream_members():
            pass


@pytest.mark.parametrize(
    ("delta", "message"),
    [(-10, "Bad magic number"), (10, "inside the members' data")],
)
def test_a_directory_size_the_entries_do_not_fill_is_refused_as_from_a_file(
    delta: int, message: str
) -> None:
    """The size places the directory, so a wrong one moves it off its entries: the
    file read refuses the archive, and so does the pass, once it reaches the end."""
    data = bytearray(_zip([("a.txt", b"one"), ("b.txt", b"two")]))
    eocd = data.index(b"PK\x05\x06")
    (size,) = struct.unpack_from("<I", data, eocd + 12)
    struct.pack_into("<I", data, eocd + 12, size + delta)
    with pytest.raises(CorruptionError, match="Bad magic number"):
        _seekable_view(bytes(data))
    with pytest.raises(CorruptionError, match=message):
        _piped_view(bytes(data))


def test_a_decoy_end_record_in_the_comment_is_the_one_used() -> None:
    """A file read takes the last end record in the tail, here a decoy for an empty
    archive in the comment; the pass takes the same, and the members it yielded are
    left out as unlisted, as a file read never lists them."""
    decoy = b"PK\x05\x06" + bytes(18)
    data = _zip([("a.txt", b"one"), ("b.txt", b"two")], comment=b"x" + decoy)
    assert _seekable_view(data) == ([], {})
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        yielded = [m.name for m, _ in reader.stream_members()]
        listed = list(reader.members_report().members)
        codes = list(reader.diagnostics.counts)
    assert (yielded, listed) == (["a.txt", "b.txt"], [])
    assert DiagnosticCode.ARCHIVE_UNLISTED_DATA in codes


@pytest.mark.parametrize(
    ("field", "at"), [("name", 28), ("extra field", 30), ("comment", 32)]
)
def test_a_field_running_past_the_directory_is_damage_as_from_a_file(
    field: str, at: int
) -> None:
    """The last entry's name, extra field or comment length runs past the
    directory's declared end: the pass stops there and raises it, as the file read
    does, where it used to read on through the end record."""
    data = bytearray(_zip([("a.txt", b"one"), ("b.txt", b"two")]))
    last = data.rindex(b"PK\x01\x02")
    struct.pack_into("<H", data, last + at, 3000)
    yielded = []
    with (
        archivey.open_archive(_pipe(bytes(data)), streaming=True) as reader,
        pytest.raises(CorruptionError, match=f"'s {field} runs"),
    ):
        for member, _ in reader.stream_members():
            yielded.append(member.name)
    assert yielded == ["a.txt", "b.txt"]


def _commented(count: int, comment_len: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(count):
            info = zipfile.ZipInfo(f"{i}.txt")
            info.comment = b"c" * comment_len
            zf.writestr(info, b"x")
    return buf.getvalue()


@pytest.mark.parametrize("source", ["pipe", "file"])
def test_directory_text_is_held_only_up_to_max_metadata_bytes(
    source: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The entries wait for the end record, which says where their offsets count
    from; their text is weighed as they arrive, so the pass holds about
    ``max_metadata_bytes`` of it, not the whole directory, and raises past it, as
    the seekable streaming pass raises on the same archive."""
    data = _commented(40, 6000)
    held: list[int] = []
    original = ZipForwardReader._charge_held_directory

    def spy(self: ZipForwardReader, nbytes: int) -> None:
        held.append(nbytes)
        original(self, nbytes)

    monkeypatch.setattr(ZipForwardReader, "_charge_held_directory", spy)
    config = archivey.ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=30_000)
    )
    opened = _pipe(data) if source == "pipe" else io.BytesIO(data)
    with archivey.open_archive(opened, streaming=True, config=config) as reader:
        yielded = []
        with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
            for member, _ in reader.stream_members():
                yielded.append(member)
    if source == "pipe":
        # The local headers hold no comment, so every member is yielded first.
        assert len(yielded) == 40
        assert len(held) == 1
        assert 30_000 < held[0] <= 30_000 + 6100
    else:
        assert len(yielded) < 40
        assert held == []


def test_a_name_that_differs_between_the_two_headers_takes_the_directory_name() -> None:
    """As from a file, where reading the member compares the two: the member reads,
    by the directory's name, and the disagreement is reported."""
    data = bytearray(_zip([("a.txt", b"one"), ("b.txt", b"two")]))
    cd = data.index(b"PK\x01\x02")
    at = data.index(b"b.txt", cd)
    data[at : at + 5] = b"c.txt"
    with archivey.open_archive(io.BytesIO(bytes(data))) as reader:
        member = reader.get("c.txt")
        assert reader.read(member) == b"two"
        assert reader.diagnostics.counts[DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS] == 1
    (from_file,) = member.diagnostics
    with archivey.open_archive(_pipe(bytes(data)), streaming=True) as reader:
        names = []
        for member, stream in reader.stream_members():
            assert stream is not None
            names.append((member.name, stream.read()))
        report = reader.members_report()
        assert reader.diagnostics.counts[DiagnosticCode.MEMBER_LOCAL_NAME_DIFFERS] == 1
    assert names == [("a.txt", b"one"), ("b.txt", b"two")]
    assert report.error is None
    assert [m.name for m in report.members] == ["a.txt", "c.txt"]
    (from_pipe,) = report.members[1].diagnostics
    assert from_pipe.context == from_file.context
    assert from_pipe.context.to_dict() == {
        "kind": "local_header",
        "archive_name": None,
        "member_name": "c.txt",
        "member_id": 1,
        "field": "name",
        "local_raw_name_base64": "Yi50eHQ=",
        "local_crc32": None,
        "local_method": None,
        "central_method": None,
    }


def test_a_name_that_differs_between_the_two_headers_is_refused_under_strict(
    tmp_path: Path,
) -> None:
    data = bytearray(_zip([("a.txt", b"one"), ("b.txt", b"two")]))
    cd = data.index(b"PK\x01\x02")
    at = data.index(b"b.txt", cd)
    data[at : at + 5] = b"c.txt"
    config = archivey.ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with archivey.open_archive(io.BytesIO(bytes(data)), config=config) as reader:
        member = reader.get("c.txt")
        # Every open raises, not only the first.
        for _ in range(2):
            with pytest.raises(DiagnosticRaisedError, match="local header stores"):
                reader.read(member)
    with (
        archivey.open_archive(
            _pipe(bytes(data)), streaming=True, config=config
        ) as reader,
        pytest.raises(DiagnosticRaisedError, match="local header stores"),
    ):
        reader.members_report()
    # Extraction stops where each read finds it: a file read at the member, the pass
    # at the directory. The pass never learned which members are links, so it takes
    # back every file it wrote that could be one (all of them here).
    for piped, expected in ((False, ["a.txt"]), (True, [])):
        dest = tmp_path / ("pipe" if piped else "file")
        source = _pipe(bytes(data)) if piped else io.BytesIO(bytes(data))
        with (
            pytest.raises(DiagnosticRaisedError),
            archivey.open_archive(source, streaming=piped, config=config) as reader,
        ):
            reader.extract_all(dest)
        assert sorted(p.name for p in dest.iterdir()) == expected


def test_too_many_local_headers_name_what_was_counted() -> None:
    data = _zip([(f"{i}.txt", b"x") for i in range(5)])
    config = archivey.ArchiveyConfig(listing_limits=ListingLimits(max_members=3))
    with (
        archivey.open_archive(_pipe(data), streaming=True, config=config) as reader,
        pytest.raises(ResourceLimitError, match="local headers"),
    ):
        for _ in reader.stream_members():
            pass


def test_a_directory_entry_with_no_local_header_fails_after_the_members() -> None:
    data = _drop_local_member(_zip([("a.txt", b"one"), ("b.txt", b"two")]), b"b.txt")
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        report = reader.members_report()
    # The local entry of b.txt is then one the directory does not list.
    assert [m.name for m in report.members] == ["a.txt"]
    assert isinstance(report.error, CorruptionError)
    assert "no local header" in str(report.error)
    (unlisted,) = [
        d
        for d in report.diagnostics.retained
        if d.code is DiagnosticCode.ARCHIVE_UNLISTED_DATA
    ]
    assert isinstance(unlisted.context, UnlistedDataContext)
    assert unlisted.context.member_name == "b.txt"


@pytest.mark.parametrize("source", ["pipe", "file"])
def test_max_members_is_charged_under_streaming(source: str) -> None:
    """From a pipe the walk charges each local header; from a file, under
    ``streaming=True``, the end record's count is refused at open."""
    data = _zip([(f"{i}.txt", b"x") for i in range(5)])
    config = archivey.ArchiveyConfig(listing_limits=ListingLimits(max_members=3))
    opened = _pipe(data) if source == "pipe" else io.BytesIO(data)
    with (
        pytest.raises(ResourceLimitError, match="max_members=3"),
        archivey.open_archive(opened, streaming=True, config=config) as reader,
    ):
        for _ in reader.stream_members():
            pass


@pytest.mark.parametrize("junk", [b"junk", b"\x01" * (1 << 20)], ids=["short", "long"])
@pytest.mark.parametrize("comment", [b"", b"thirteen byte"])
def test_bytes_after_the_end_record_are_reported_as_from_a_file(
    comment: bytes, junk: bytes
) -> None:
    """The report names where the junk starts after the record and its comment, also
    behind more junk than the end-record search reads."""
    data = _zip([("a.txt", b"one")], comment=comment) + b"\x00\x00" + junk

    def trailing(source: object, streaming: bool) -> list[object]:
        with archivey.open_archive(source, streaming=streaming) as reader:  # type: ignore[arg-type]
            reader.members_report()
            return [
                d.context
                for d in reader.diagnostics.retained
                if d.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
            ]

    from_pipe = trailing(_pipe(data), True)
    assert from_pipe == trailing(io.BytesIO(data), False)
    assert [c.observed_bytes for c in from_pipe] == [2]  # type: ignore[attr-defined]


def test_a_stream_that_is_no_zip_fails_at_open() -> None:
    with pytest.raises(CorruptionError):
        archivey.open_archive(
            _pipe(b"PK\x03\x04" + b"\xff" * 100), streaming=True, format="zip"
        )


def test_an_encrypted_member_fails_when_read_as_from_a_file_and_is_skipped() -> None:
    plain = _zip([("a.txt", b"one"), ("b.txt", b"two")], method=zipfile.ZIP_STORED)
    data = bytearray(plain)
    # Set the encryption bit on a.txt in both headers; its data is then "ciphertext",
    # too short to hold a ZipCrypto header.
    data[6] |= 0x01
    cd = data.index(b"PK\x01\x02")
    data[cd + 8] |= 0x01
    for password, error, match in (
        (None, EncryptionError, "Password required"),
        ("pw", CorruptionError, "too short"),
    ):
        with (
            archivey.open_archive(io.BytesIO(bytes(data)), password=password) as rd,
            pytest.raises(error, match=match),
        ):
            rd.read(rd.members()[0])
        with archivey.open_archive(
            _pipe(bytes(data)), streaming=True, password=password
        ) as reader:
            passes = reader.stream_members()
            member, stream = next(passes)
            assert member.is_encrypted and stream is not None
            with pytest.raises(error, match=match):
                stream.read()
            assert [m.name for m, _ in passes] == ["b.txt"]


def test_a_bit3_lzma_member_with_no_end_marker_is_refused() -> None:
    """Its decoded data cannot find its end; its read is refused, and the walk's scan
    finds the end on the stored bytes so the pass goes on."""
    import lzma

    filt = {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 16}
    props = lzma._encode_filter_properties(filt)  # type: ignore[attr-defined]
    body = struct.pack("<BBH", 9, 20, len(props)) + props
    body += lzma.compress(b"abc" * 100, format=lzma.FORMAT_RAW, filters=[filt])
    name = b"a.bin"
    crc = zlib.crc32(b"abc" * 100)
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 63, 0x08, 14, 0, 0x21, 0, 0, 0, len(name), 0
    )
    member = local + name + body
    member += struct.pack("<IIII", 0x08074B50, crc, len(body), 300)
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, 63, 63, 0x08, 14, 0, 0x21, crc, len(body),
        300, len(name), 0, 0, 0, 0, 0, 0,
    ) + name  # fmt: skip
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(member), 0)
    data = member + central + end
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        for _, stream in reader.stream_members():
            assert stream is not None
            with pytest.raises(UnsupportedFeatureError, match="end-of-stream marker"):
                stream.read()
        assert [m.name for m in reader.members_report().members] == ["a.bin"]


def _reparse_zip(data: bytes) -> bytes:
    from archivey.internal.windows_reparse import FILE_ATTRIBUTE_REPARSE_POINT

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("tree/entry")
        info.create_system = 0
        info.external_attr = 0x20 | FILE_ATTRIBUTE_REPARSE_POINT
        zf.writestr(info, data)
        zf.writestr("tree/after.txt", b"next member")
    return buf.getvalue()


def test_a_reparse_member_whose_data_is_no_link_stays_a_file() -> None:
    """From a pipe the reparse flag arrives after the data, so the member is yielded
    as a file with its content, and the directory leaves it one."""
    content = b"not a reparse buffer " * 10
    with archivey.open_archive(_pipe(_reparse_zip(content)), streaming=True) as reader:
        got = [
            (m.type, s.read() if s is not None else None)
            for m, s in reader.stream_members()
        ]
        entry = reader.members_report().members[0]
    assert got[0] == (MemberType.FILE, content)
    assert entry.type is MemberType.FILE


def test_a_reparse_member_holding_a_link_buffer_becomes_a_link() -> None:
    from archivey.internal.windows_reparse import IO_REPARSE_TAG_SYMLINK
    from tests.test_windows_reparse import _reparse_buffer

    buffer = _reparse_buffer(IO_REPARSE_TAG_SYMLINK, "after.txt", "after.txt")
    with archivey.open_archive(_pipe(_reparse_zip(buffer)), streaming=True) as reader:
        entry = reader.members_report().members[0]
    assert (entry.type, entry.link_target) == (MemberType.SYMLINK, "after.txt")


def test_a_stub_in_front_of_the_archive_is_read_past() -> None:
    stub = b"MZ" + b"\x90" * 5000
    data = stub + _zip([("a.txt", b"one")])
    with archivey.open_archive(_pipe(data), streaming=True, format="zip") as reader:
        report = reader.members_report()
    assert report.error is None
    assert [m.name for m in report.members] == ["a.txt"]


# -- What the directory finds at the end of the pass ---------------------------------


class _Hand:
    """A ZIP written by hand: local entries in file order, then a directory listing
    whichever of them a test names, in the order it names them."""

    def __init__(self) -> None:
        self.data = bytearray()
        # name -> (offset, flags, crc, compressed size, size), per local entry.
        self.locals: list[tuple[bytes, int, int, int, int, int]] = []

    def local(
        self,
        name: bytes,
        data: bytes,
        *,
        bit3: bool = False,
        crc: int | None = None,
        sizes: tuple[int, int] | None = None,
    ) -> None:
        """A stored local entry. ``crc`` and ``sizes`` replace what its header says
        (and, for a bit-3 entry, what the directory will say); a bit-3 entry gets a
        signed descriptor with its true CRC and size after its data."""
        true_crc = zlib.crc32(data)
        crc = true_crc if crc is None else crc
        csize, size = (len(data), len(data)) if sizes is None else sizes
        flags = 0x08 if bit3 else 0
        offset = len(self.data)
        in_header = (0, 0, 0) if bit3 else (crc, csize, size)
        self.data += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, flags, 0, 0, 0x21, *in_header, len(name), 0
        )
        self.data += name + data
        if bit3:
            self.data += struct.pack(
                "<IIII", 0x08074B50, true_crc, len(data), len(data)
            )
        self.locals.append((name, offset, flags, crc, csize, size))

    def raw(self, data: bytes) -> None:
        self.data += data

    def directory(self, *order: int) -> bytes:
        """The archive, its directory listing the local entries at ``order``."""
        cd_offset = len(self.data)
        cd = bytearray()
        for i in order:
            name, offset, flags, crc, csize, size = self.locals[i]
            cd += struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50, 20, 20, flags, 0, 0, 0x21, crc, csize, size,
                len(name), 0, 0, 0, 0, 0, offset,
            )  # fmt: skip
            cd += name
        count = len(order)
        end = struct.pack(
            "<IHHHHIIH", 0x06054B50, 0, 0, count, count, len(cd), cd_offset, 0
        )
        return bytes(self.data + cd + end)


def _listing(data: bytes, *, pipe: bool) -> archivey.MemberListReport:
    source = _pipe(data) if pipe else io.BytesIO(data)
    with archivey.open_archive(source, streaming=pipe) as reader:
        return reader.members_report()


def _unlisted(report: archivey.MemberListReport) -> list[UnlistedDataContext]:
    out = []
    for d in report.diagnostics.retained:
        if d.code is DiagnosticCode.ARCHIVE_UNLISTED_DATA:
            assert isinstance(d.context, UnlistedDataContext)
            out.append(d.context)
    return out


def test_a_local_entry_the_directory_does_not_list_is_dropped_and_reported() -> None:
    hand = _Hand()
    hand.local(b"a.txt", b"one")
    hand.local(b"planted.txt", b"not listed")
    hand.local(b"b.txt", b"two")
    data = hand.directory(0, 2)
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        yielded = [m for m, _ in reader.stream_members()]
        report = reader.members_report()
    assert [m.name for m in yielded] == ["a.txt", "planted.txt", "b.txt"]
    assert report.error is None
    assert [m.name for m in report.members] == ["a.txt", "b.txt"]
    assert [m.name for m in report.members] == [
        m.name for m in _listing(data, pipe=False).members
    ]
    planted = yielded[1]
    # It leaves the listing; the report is what says why.
    assert planted.member_state_final
    assert all(m is not planted for m in report.members)
    (context,) = _unlisted(report)
    assert (context.member_name, context.member_id) == ("planted.txt", 1)
    assert (context.offset, context.compressed_size) == (hand.locals[1][1], 10)
    assert context.format == "zip"


def test_an_unlisted_local_entry_is_refused_under_strict() -> None:
    hand = _Hand()
    hand.local(b"a.txt", b"one")
    hand.local(b"planted.txt", b"not listed")
    data = hand.directory(0)
    strict = archivey.ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT)
    with (
        archivey.open_archive(_pipe(data), streaming=True, config=strict) as reader,
        pytest.raises(DiagnosticRaisedError),
    ):
        reader.members_report()


# -- Bytes after a member that are no local header -----------------------------------


def _insert(data: bytes, at: int, gap: bytes) -> bytes:
    """``data`` with ``gap`` inserted at offset ``at``, between two members, and the
    directory's offsets moved to match, as a writer that left the bytes there
    records them."""
    out = bytearray(data[:at] + gap + data[at:])
    eocd = out.rindex(b"PK\x05\x06")
    count, _, cd_offset = struct.unpack_from("<HII", out, eocd + 10)
    cd = cd_offset + len(gap)
    struct.pack_into("<I", out, eocd + 16, cd)
    for _ in range(count):
        (offset,) = struct.unpack_from("<I", out, cd + 42)
        if offset >= at:
            struct.pack_into("<I", out, cd + 42, offset + len(gap))
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", out, cd + 28)
        cd += 46 + name_len + extra_len + comment_len
    return bytes(out)


def _read_one(data: bytes, *, pipe: bool) -> tuple[list[tuple[str, bytes]], object]:
    """Each listed member's name and data, and the listing's error."""
    source = _pipe(data) if pipe else io.BytesIO(data)
    with archivey.open_archive(source, streaming=True, format="zip") as reader:
        read = [
            (m.name, stream.read())
            for m, stream in reader.stream_members()
            if stream is not None
        ]
        report = reader.members_report()
    listed = {m.name for m in report.members}
    return [r for r in read if r[0] in listed], report.error


def _read_both(data: bytes) -> list[tuple[list[tuple[str, bytes]], object]]:
    """:func:`_read_one` from a file, then from a pipe."""
    return [_read_one(data, pipe=pipe) for pipe in (False, True)]


@pytest.mark.parametrize(
    "gap",
    [
        pytest.param(b"\x00" * 16, id="zeros"),
        pytest.param(b"junkjunk", id="junk"),
        # A descriptor a writer appended to a member whose sizes are in its header.
        pytest.param(b"PK\x07\x08" + b"\x00" * 12, id="stray-descriptor"),
        pytest.param(b"PK\x01\x02junk", id="directory-signature"),
        pytest.param(b"PK\x05\x06" + b"\x00" * 18, id="end-record-signature"),
    ],
)
@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_bytes_between_two_members_do_not_end_the_pass(gap: bytes, method: int) -> None:
    """The walk stops at bytes after a member that are no local header, and keeps
    what follows. The members the directory places there are read from those bytes,
    as a file read seeks to them."""
    data = _zip(
        [("a.txt", b"one"), ("b.txt", b"two"), ("c.txt", b"three")], method=method
    )
    second = data.index(b"PK\x03\x04", 1)
    data = _insert(data, second, gap)
    expected = [("a.txt", b"one"), ("b.txt", b"two"), ("c.txt", b"three")]
    assert _read_both(data) == [(expected, None), (expected, None)]


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_bytes_after_a_bit3_member_still_end_the_pass(method: int) -> None:
    """A recorded difference: a bit-3 member's descriptor counts only when a ZIP
    signature follows it, which is what stops a descriptor planted in its data. Bytes
    between it and the next member leave the pass no end for its data; a file read
    knows its size and reads every member."""
    data = _streamed(_zip([("a.txt", b"one" * 50), ("b.txt", b"two")], method=method))
    second = data.index(b"PK\x03\x04", 1)
    data = _insert(data, second, b"\x00" * 16)
    expected = [("a.txt", b"one" * 50), ("b.txt", b"two")]
    assert _read_one(data, pipe=False) == (expected, None)
    with pytest.raises((CorruptionError, UnsupportedFeatureError)):
        _read_one(data, pipe=True)


def test_two_concatenated_archives_read_the_second_from_a_pipe(tmp_path: Path) -> None:
    """``cat first.zip second.zip``: a file read takes the last end record and the
    second archive's members, as ``unzip`` does. The pass reads the first archive's
    members as it meets them, then the second's from the bytes it kept after them;
    the first's are not in the listing, and are reported."""
    first = _zip([("a.txt", b"one"), ("b.txt", b"two")])
    second = _zip([("c.txt", b"three"), ("d.txt", b"four")])
    data = first + second
    expected = [("c.txt", b"three"), ("d.txt", b"four")]
    assert _read_both(data) == [(expected, None), (expected, None)]
    report = _listing(data, pipe=True)
    assert [c.member_name for c in _unlisted(report)] == ["a.txt", "b.txt"]
    for pipe in (False, True):
        dest = tmp_path / str(pipe)
        source = _pipe(data) if pipe else io.BytesIO(data)
        with archivey.open_archive(source, streaming=True, format="zip") as reader:
            reader.extract_all(dest)
        assert sorted(p.name for p in dest.iterdir()) == ["c.txt", "d.txt"]


def test_a_member_past_the_bytes_the_pass_holds_is_a_resource_limit() -> None:
    """The second archive's first member runs into the bytes the listing limits
    drop: higher limits keep them, so the pass refuses with ``ResourceLimitError``,
    as for a directory there."""
    first = _zip([("a.txt", b"one")], method=zipfile.ZIP_STORED)
    second = _zip(
        [("c.txt", random.Random(0).randbytes(1 << 20)), ("d.txt", b"four")],
        method=zipfile.ZIP_STORED,
    )
    config = archivey.ArchiveyConfig(
        listing_limits=ListingLimits(max_members=4, max_metadata_bytes=200)
    )
    with (
        archivey.open_archive(
            _pipe(first + second), streaming=True, format="zip", config=config
        ) as reader,
        pytest.raises(ResourceLimitError, match="past the members"),
    ):
        for _ in reader.stream_members():
            pass


def _overlapping_held_members(n: int) -> bytes:
    """One sized member, four bytes that are no local header (the walk ends there),
    then ``n`` local headers whose data each runs to the end of the stream, and a
    directory naming them all: each held member's data covers every later one."""
    first = (
        struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, zlib.crc32(b"x"), 1, 1, 1, 0
        )
        + b"ax"
    )
    body = bytearray(first + b"JUNK")
    offsets = [0]
    names = [b"a"]
    for i in range(n):
        offsets.append(len(body))
        names.append(b"m%06d" % i)
        body += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, 0, 0, 0, 7, 0
        )
        body += names[-1]
    size = len(_with_directory(body, names, offsets))
    # Each held header's data runs from its data start to the end of the stream.
    for offset, name in zip(offsets[1:], names[1:], strict=True):
        data_start = offset + 30 + len(name)
        struct.pack_into("<II", body, offset + 18, size - data_start, size - data_start)
    return _with_directory(body, names, offsets)


def _rejected_held_headers(n: int) -> bytes:
    """One sized member, four bytes that end the walk, then ``n`` local headers 30
    bytes apart that do not parse: each names a 65 535-byte name, read over the
    headers after it, and declares 4 GiB sizes with no ZIP64 extra field. Padding
    keeps the last name inside the stream, and a directory names them all."""
    body = bytearray(
        struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, zlib.crc32(b"x"), 1, 1, 1, 0
        )
        + b"axJUNK"
    )
    offsets = [0]
    names = [b"a"]
    for i in range(n):
        offsets.append(len(body))
        names.append(b"h%06d" % i)
        body += struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50, 20, 0, 0, 0, 0x21, 0, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF, 0,
        )  # fmt: skip
    body += b"\x00" * (0xFFFF + 64)
    return _with_directory(body, names, offsets)


def _with_directory(body: bytearray, names: list[bytes], offsets: list[int]) -> bytes:
    """``body`` with a directory naming each of ``names`` at its offset; the first
    is the one-byte STORED ``a``."""
    cd = bytearray()
    for name, offset in zip(names, offsets, strict=True):
        crc, size = (zlib.crc32(b"x"), 1) if offset == 0 else (0, 0)
        cd += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50, 20, 20, 0, 0, 0, 0x21, crc, size, size,
            len(name), 0, 0, 0, 0, 0, offset,
        ) + name  # fmt: skip
    count = len(names)
    end = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, count, count, len(cd), len(body), 0
    )
    return bytes(body + cd + end)


def _count_held_reads(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """A one-item list holding how many bytes the walks over held members read."""
    read = [0]
    original = zip_local_walk._HeldBytes.read

    def counting(self: zip_local_walk._HeldBytes, n: int = -1, /) -> bytes:
        chunk = original(self, n)
        read[0] += len(chunk)
        return chunk

    monkeypatch.setattr(zip_local_walk._HeldBytes, "read", counting)
    return read


@pytest.mark.parametrize(
    "limits", [ListingLimits(), ListingLimits.UNLIMITED], ids=["default", "unlimited"]
)
@pytest.mark.parametrize(
    "build", [_overlapping_held_members, _rejected_held_headers],
    ids=["overlapping-data", "rejected-headers"],
)  # fmt: skip
def test_held_entries_read_the_kept_bytes_at_most_twice(
    monkeypatch: pytest.MonkeyPatch,
    build: Callable[[int], bytes],
    limits: ListingLimits,
) -> None:
    """Entries whose bytes overlap would each read on past the next ones: members
    whose data runs to the end of the stream, or local headers whose names run
    over the headers after them and then do not parse. Every byte an attempt reads
    is counted, and once the count reaches the bytes held the next entry is
    refused before it is read. Overlap is malformed input, so the refusal is
    ``CorruptionError`` at any listing limit."""
    data = build(1000)
    read = _count_held_reads(monkeypatch)
    config = archivey.ArchiveyConfig(listing_limits=limits)
    with (
        archivey.open_archive(
            _pipe(data), streaming=True, format="zip", config=config
        ) as reader,
        pytest.raises(CorruptionError, match="overlap"),
    ):
        for _ in reader.stream_members():
            pass
    assert read[0] <= 2 * len(data)


def _cheap_rejected_held_headers(n: int, *, header: bool = True) -> bytes:
    """``n`` 30-byte local headers after the walk's end that fail to parse after
    their fixed part (4 GiB sizes, no ZIP64 extra field), or, without ``header``,
    the same number of bytes holding no local header."""
    body = bytearray(
        struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, zlib.crc32(b"x"), 1, 1, 1, 0
        )
        + b"axJUNK"
    )
    offsets = [0]
    names = [b"a"]
    for i in range(n):
        offsets.append(len(body))
        names.append(b"h%06d" % i)
        if header:
            body += struct.pack(
                "<IHHHHHIIIHH",
                0x04034B50, 20, 0, 0, 0, 0x21, 0, 0xFFFF_FFFF, 0xFFFF_FFFF, 0, 0,
            )  # fmt: skip
        else:
            body += b"QQQQ" + b"\x00" * 26
    return _with_directory(body, names, offsets)


def test_a_rejected_held_header_keeps_no_frames() -> None:
    """Each rejected header's error is kept until the end of the pass, for its
    entry's failure; its traceback would keep the parse's frames alive, one chain
    per entry. The pass holds no more for rejected headers than for entries with
    no header at all, give or take the error objects."""
    n = 2000

    def peak(data: bytes) -> int:
        def list_members() -> None:
            with archivey.open_archive(
                _pipe(data), streaming=True, format="zip"
            ) as reader:
                report = reader.members_report()
            assert isinstance(report.error, CorruptionError)

        return traced_peak(list_members)

    # traced_peak leaves first-use costs (lazy imports, caches) to its caller; a warm-up
    # pass keeps them off the first measurement, which is the larger side.
    peak(_cheap_rejected_held_headers(1))
    rejected = peak(_cheap_rejected_held_headers(n))
    missing = peak(_cheap_rejected_held_headers(n, header=False))
    assert rejected - missing < n * 2048


def test_a_rejected_held_header_leaves_the_callers_exception_alone() -> None:
    """A pass driven inside the caller's ``except`` block raises its parse errors
    with the caller's exception as their context. Keeping such an error drops the
    reader's own frames, never those of the caller's exception."""
    data = _cheap_rejected_held_headers(1)
    try:
        raise ValueError("the caller's own error")
    except ValueError as caller_exc:
        with archivey.open_archive(_pipe(data), streaming=True, format="zip") as reader:
            assert isinstance(reader.members_report().error, CorruptionError)
        assert caller_exc.__traceback__ is not None


def test_a_held_local_header_that_does_not_parse_says_why() -> None:
    """A local header is there but does not parse: its entry fails, naming the
    parse error rather than saying the stream held none."""
    data = _rejected_held_headers(1)
    with archivey.open_archive(_pipe(data), streaming=True, format="zip") as reader:
        report = reader.members_report()
    assert [m.name for m in report.members] == ["a"]
    error = report.error
    assert isinstance(error, CorruptionError)
    assert "held no local header" not in str(error)
    assert "did not parse" in str(error)
    assert isinstance(error.__cause__, CorruptionError)


def test_a_held_member_is_numbered_after_the_walked_ones() -> None:
    """A member read from the kept bytes keeps its place in the pass's numbering,
    in the messages that quote it."""
    first = _zip([("a.txt", b"one")], method=zipfile.ZIP_STORED)
    second = bytearray(
        _zip([("c.txt", b"three"), ("d.txt", b"four")], method=zipfile.ZIP_STORED)
    )
    # c.txt's local header claims more data than the stream holds.
    struct.pack_into("<II", second, 18, 1_000_000, 1_000_000)
    with (
        archivey.open_archive(
            _pipe(first + bytes(second)), streaming=True, format="zip"
        ) as reader,
        pytest.raises(CorruptionError, match=r"member #1\b"),
    ):
        for _ in reader.stream_members():
            pass


def test_a_stub_before_an_archive_with_no_local_header_opens_empty() -> None:
    """No local header within the stub scan's window, but an end record: as from a
    file, the archive opens with what its directory lists."""
    empty = io.BytesIO()
    zipfile.ZipFile(empty, "w").close()
    data = b"MZ" + b"\x00" * 5000 + empty.getvalue()
    for pipe in (False, True):
        source = _pipe(data) if pipe else io.BytesIO(data)
        with archivey.open_archive(source, streaming=True, format="zip") as reader:
            report = reader.members_report()
        assert (list(report.members), report.error) == ([], None)


def test_the_later_copy_in_the_directory_is_current() -> None:
    """Two members of one name whose directory order reverses their file order: the
    one the directory lists last is current, as from a file, and the pass raises
    nothing, as ``member_state_final`` said the members could still change."""
    hand = _Hand()
    hand.local(b"dup.txt", b"first")
    hand.local(b"dup.txt", b"second")
    data = hand.directory(1, 0)
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        during = []
        for member, stream in reader.stream_members():
            assert stream is not None
            during.append((stream.read(), member.is_current))
        report = reader.members_report()
    assert during == [(b"first", True), (b"second", True)]
    assert report.error is None
    # Members stay in file order, with the ids the pass gave them.
    assert [(m.size, m.is_current) for m in report.members] == [(5, True), (6, False)]
    with archivey.open_archive(io.BytesIO(data)) as reader:
        assert reader.open("dup.txt").read() == b"first"


def _planted_prefix_zip() -> tuple[bytes, bytes]:
    """A STORED bit-3 member whose data embeds a valid descriptor for a prefix of
    itself, then a local header: from a pipe the scan ends the member at the planted
    descriptor and reads on into a member the directory does not list. Returns the
    archive and the member's whole data."""
    prefix = b"prefix bytes"
    planted = struct.pack(
        "<IIII", 0x08074B50, zlib.crc32(prefix), len(prefix), len(prefix)
    )
    inner = b"inner data"
    # The inner entry's size runs over the outer member's own descriptor, up to the
    # next local header; its CRC is not checked by a pass that skips it.
    inner_header = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0x21, 0, len(inner) + 16,
        len(inner) + 16, 5, 0,
    ) + b"inner"  # fmt: skip
    whole = prefix + planted + inner_header + inner
    hand = _Hand()
    hand.local(b"outer.bin", whole, bit3=True)
    hand.local(b"after.txt", b"after")
    return hand.directory(0, 1), whole


def test_a_descriptor_the_directory_contradicts_fails_at_the_end_of_the_pass() -> None:
    data, whole = _planted_prefix_zip()
    with archivey.open_archive(io.BytesIO(data)) as reader:
        assert reader.open("outer.bin").read() == whole
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        names = []
        with pytest.raises(CorruptionError, match="data descriptor") as raised:
            for member, stream in reader.stream_members():
                names.append(member.name)
                if stream is not None and member.name == "outer.bin":
                    assert stream.read() == b"prefix bytes"
        report = reader.members_report()
    assert names == ["outer.bin", "inner", "after.txt"]
    assert raised.value.member_name == "outer.bin"
    assert report.error is raised.value
    # As the directory describes it, and as the seekable read lists it.
    assert [(m.name, m.size) for m in report.members] == [
        ("outer.bin", len(whole)),
        ("after.txt", 5),
    ]
    assert [c.member_name for c in _unlisted(report)] == ["inner"]


@pytest.mark.parametrize(
    "limit",
    [
        pytest.param(100_000, id="members-overfill"),
        pytest.param(20_000, id="held-text-overfills"),
    ],
)
def test_a_directory_that_takes_the_listing_over_the_limits_ends_the_pass(
    limit: int,
) -> None:
    """The directory arrives after the last member, so the pass yields every member
    and then raises ``ResourceLimitError``: whether the members the directory updates
    overfill the listing, or the directory's text overfills it while it is held,
    before any member is updated."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # Long names take the updated members over 100 000 bytes; short ones keep
        # the walk under 20 000, which the held comments then pass.
        stem = "n" * 1900 if limit == 100_000 else "n"
        for i in range(20):
            info = zipfile.ZipInfo(f"{i}-{stem}.txt")
            info.comment = b"c" * 2000
            zf.writestr(info, b"x")
    config = archivey.ArchiveyConfig(
        listing_limits=ListingLimits(max_metadata_bytes=limit)
    )
    with archivey.open_archive(
        _pipe(buf.getvalue()), streaming=True, config=config
    ) as reader:
        yielded = []
        with pytest.raises(ResourceLimitError, match="max_metadata_bytes"):
            for member, _ in reader.stream_members():
                yielded.append(member)
        assert len(yielded) == 20


def _with_zip64_extensible(data: bytes, extensible: int) -> bytes:
    """``data`` with a ZIP64 end record and locator before its end record, the record
    carrying ``extensible`` bytes of extensible data: bytes after the directory that no
    listing limit counts."""
    eocd = data.rindex(b"PK\x05\x06")
    entries, cd_size, cd_offset = struct.unpack_from("<HII", data, eocd + 10)
    record = struct.pack(
        "<4sQHHIIQQQQ",
        b"PK\x06\x06",
        44 + extensible,
        45,
        45,
        0,
        0,
        entries,
        entries,
        cd_size,
        cd_offset,
    ) + bytes(extensible)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, eocd, 1)
    return data[:eocd] + record + locator + data[eocd:]


def _with_bytes_before_directory(data: bytes, gap: int) -> bytes:
    """``data`` with ``gap`` bytes between its last member and its directory, the end
    record's directory offset moved past them: what no listing limit counts."""
    eocd = data.rindex(b"PK\x05\x06")
    (cd_offset,) = struct.unpack_from("<I", data, eocd + 16)
    out = bytearray(data[:cd_offset] + b"\x01" * gap + data[cd_offset:])
    struct.pack_into("<I", out, eocd + gap + 16, cd_offset + gap)
    return bytes(out)


def test_a_directory_further_back_than_the_listing_limits_allow_is_a_limit() -> None:
    """The pass keeps what a directory within the listing limits takes, plus room for
    the records after it, at both ends of what follows the members: a directory right
    after them is read however much junk follows the end record, as long as the step
    from it to the end record stays in the kept bytes; past them, or for a directory
    further from both ends, it is out of reach."""
    limits = ListingLimits(max_members=2, max_metadata_bytes=200_000)
    config = archivey.ArchiveyConfig(listing_limits=limits)
    plain = _zip([("a.txt", b"one"), ("b.txt", b"two")])
    # What the pass keeps at each end: two 46-byte headers, the text the limit
    # allows, and four end-record search windows. After the directory (102 bytes)
    # come the ZIP64 end record (56 and its extensible data), its locator (20) and
    # the end record (22): 200 bytes and the extensible data.
    keep = 2 * 46 + 200_000 + 4 * 65_558
    far = _with_zip64_extensible(plain, keep - 200 + 100)
    # The same, with bytes between the members and the directory: the directory and
    # the ZIP64 end record after it are past what the pass keeps after the members.
    out_of_reach = _with_zip64_extensible(
        _with_bytes_before_directory(plain, keep + 1000), keep - 200 + 100
    )
    for data in (far, out_of_reach):
        assert [m["name"] for m in _seekable_view(data)[0]] == ["a.txt", "b.txt"]
    # And with more junk after the end record than the pass keeps at the end.
    junk_after = plain + b"\x01" * (2 * keep)
    for data in (far, junk_after):
        with archivey.open_archive(
            _pipe(data), streaming=True, config=config
        ) as reader:
            assert [m.name for m, _ in reader.stream_members()] == ["a.txt", "b.txt"]
            listed = reader.members_report().members
            assert [m.name for m in listed] == ["a.txt", "b.txt"]
    # The ZIP64 end record itself out of reach: the locator names it in bytes the
    # bound dropped.
    record_dropped = _with_zip64_extensible(
        _with_bytes_before_directory(plain, keep + 1000), keep + 5000
    )
    assert [m["name"] for m in _seekable_view(record_dropped)[0]] == ["a.txt", "b.txt"]
    # A record signature right before the locator, in the extensible data: the
    # file read's fallback for prepended data takes only a whole record that fits
    # the locator, so the record the locator names is still the one out of reach.
    adjacent = len(record_dropped) - 22 - 20 - 56
    decoy = record_dropped[:adjacent] + b"PK\x06\x06" + record_dropped[adjacent + 4 :]
    assert [m["name"] for m in _seekable_view(decoy)[0]] == ["a.txt", "b.txt"]
    # A whole record there that fits the locator: a file read still reads the one
    # the locator names, as no stub moved the archive (its first member is at 0).
    (named,) = struct.unpack_from("<Q", record_dropped, len(record_dropped) - 22 - 12)
    cd_size = 102
    whole_record = struct.pack(
        "<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, 2, 2, cd_size, named - cd_size
    )
    whole = record_dropped[:adjacent] + whole_record + record_dropped[adjacent + 56 :]
    assert [m["name"] for m in _seekable_view(whole)[0]] == ["a.txt", "b.txt"]
    # The directory right after the members, but its ZIP64 end record's extensible
    # data runs past the bytes kept after them, and junk past the search window
    # after the end record: a file read steps on to the end record.
    far_and_junk = far + b"\x01" * (2 * keep)
    assert [m["name"] for m in _seekable_view(far_and_junk)[0]] == ["a.txt", "b.txt"]
    # A locator with no ZIP64 record, naming an offset in the bytes the bound
    # dropped, after a classic record that needs none of its fields: a file read
    # finds no record there and lets the classic record stand in. The pass cannot
    # tell what those bytes hold, so it refuses rather than stand in: higher limits
    # keep them.
    spaced = _with_bytes_before_directory(plain, 2 * keep + 1000)
    eocd = spaced.rindex(b"PK\x05\x06")
    (cd_offset,) = struct.unpack_from("<I", spaced, eocd + 16)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, cd_offset - keep - 500, 1)
    lone_locator = spaced[:eocd] + locator + spaced[eocd:]
    assert [m["name"] for m in _seekable_view(lone_locator)[0]] == ["a.txt", "b.txt"]
    cases = (
        (lone_locator, "ZIP64 end of central directory record starts"),
        (far_and_junk, "ZIP directory and end records run past"),
        (out_of_reach, "ZIP central directory starts"),
        (record_dropped, "ZIP64 end of central directory record starts"),
        (decoy, "ZIP64 end of central directory record starts"),
        (whole, "ZIP64 end of central directory record starts"),
    )
    for data, what in cases:
        with (
            pytest.raises(ResourceLimitError, match=f"^{what}.*listing limits"),
            archivey.open_archive(_pipe(data), streaming=True, config=config) as reader,
        ):
            for _ in reader.stream_members():
                pass


def _zip64_record_in_member_data() -> bytes:
    """One member whose data holds a directory listing it, then a ZIP64 end record
    naming that directory; the archive ends with a locator naming the record."""
    name = b"x.txt"
    data_at = 30 + len(name)
    entry_size = 46 + len(name)
    member_size = entry_size + 56
    central = struct.pack(
        "<4sHHHHHHIIIHHHHHII",
        b"PK\x01\x02", 20, 20, 0, 0, 0, 0, 0, member_size, member_size,
        len(name), 0, 0, 0, 0, 0, 0,
    ) + name  # fmt: skip
    record_at = data_at + entry_size
    record = struct.pack(
        "<4sQHHIIQQQQ",
        b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, entry_size, data_at,
    )  # fmt: skip
    local = struct.pack(
        "<4sHHHHHIIIHH",
        b"PK\x03\x04", 20, 0, 0, 0, 0, 0, member_size, member_size, len(name), 0,
    ) + name  # fmt: skip
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, record_at, 1)
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 1, 1, entry_size, data_at, 0)
    return local + central + record + locator + eocd


def test_a_zip64_end_record_among_the_members_data_is_refused() -> None:
    """A locator naming a record the pass read past, inside a member's data: a file
    read and stdlib list the archive by it; the pass cannot see it, and says so
    rather than calling it missing."""
    data = _zip64_record_in_member_data()
    assert zipfile.ZipFile(io.BytesIO(data)).namelist() == ["x.txt"]
    # The member's data is the directory, so reading it is an overlap: compare the
    # listing only.
    assert [m["name"] for m in _seekable_view(data, read=False)[0]] == ["x.txt"]
    message = "ZIP64 end of central directory record.* inside the members' data"
    with (
        pytest.raises(CorruptionError, match=message),
        archivey.open_archive(_pipe(data), streaming=True) as reader,
    ):
        for _ in reader.stream_members():
            pass


@pytest.mark.parametrize("field", ["disks", "disk_with_record"])
def test_a_split_set_locator_is_refused_before_the_record_is_looked_for(
    field: str,
) -> None:
    """The locator's disk fields are refused as a split set first, as from a file,
    wherever the record it names is."""
    data = bytearray(_zip64_record_in_member_data())
    locator_at = data.rindex(b"PK\x06\x07")
    if field == "disks":
        struct.pack_into("<I", data, locator_at + 16, 2)
    else:
        struct.pack_into("<I", data, locator_at + 4, 7)
    for source, streaming in (
        (io.BytesIO(bytes(data)), False),
        (_pipe(bytes(data)), True),
    ):
        with (
            pytest.raises(UnsupportedFeatureError, match="Multi-volume"),
            archivey.open_archive(source, streaming=streaming) as reader,
        ):
            for _ in reader.stream_members():
                pass


def test_a_zip64_archive_behind_a_stub_lists_from_a_pipe() -> None:
    """A self-extractor stub in front of a ZIP64 archive whose offsets omit it: the
    locator names the record where it was before the stub, among the members' data,
    and the record right before the locator is the one a file read takes."""
    plain = _zip([("a.txt", b"one"), ("b.txt", b"two")])
    data = b"MZ" + b"\x90" * 5000 + _with_zip64_extensible(plain, 0)
    assert [m["name"] for m in _seekable_view(data)[0]] == ["a.txt", "b.txt"]
    assert _piped_view(data) == _seekable_view(data)


def test_a_record_hidden_by_the_stub_is_read_only_by_a_file_read_told_the_format() -> (
    None
):
    """A whole record planted inside the stub, at the offset the locator names. With
    detection the file read slices the stub off and agrees with the pipe; told the
    format, it reads the planted record, which a pipe that kept only the bytes after
    the members cannot see (``ForwardTail._refuse_unseen_zip64_record``)."""
    plain = _zip([("a.txt", b"one"), ("b.txt", b"two")])
    eocd = plain.rindex(b"PK\x05\x06")
    entries, cd_size, cd_offset = struct.unpack_from("<HII", plain, eocd + 10)
    data = bytearray(b"MZ" + b"\x90" * 5000 + _with_zip64_extensible(plain, 0))
    extensible = (len(data) - 22 - 20 - 56) - eocd
    data[eocd : eocd + 56] = struct.pack(
        "<4sQHHIIQQQQ", b"PK\x06\x06", 44 + extensible, 45, 45, 0, 0,
        entries, entries, cd_size, cd_offset,
    )  # fmt: skip
    data = bytes(data)
    names = ["a.txt", "b.txt"]
    assert [m["name"] for m in _seekable_view(data)[0]] == names
    assert [m["name"] for m in _piped_view(data)[0]] == names
    with (
        pytest.raises(CorruptionError, match="Bad magic number"),
        archivey.open_archive(io.BytesIO(data), format="zip") as reader,
    ):
        reader.members()


def test_a_header_offset_past_what_the_array_holds_is_a_missing_member() -> None:
    """A ZIP64 extra field may put a local header offset anywhere in 64 bits: past
    ``MAX_DATA_OFFSET`` it points at no local header, as from a file."""
    data = bytearray(_zip([("a.txt", b"one")], method=zipfile.ZIP_STORED))
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<I", data, central + 42, 0xFFFF_FFFF)
    name_len, extra_len = struct.unpack_from("<HH", data, central + 28)
    assert extra_len == 0
    extra = struct.pack("<HHQ", 1, 8, 1 << 63)
    struct.pack_into("<H", data, central + 30, len(extra))
    at = central + 46 + name_len
    data[at:at] = extra
    eocd = data.rindex(b"PK\x05\x06")
    (cd_size,) = struct.unpack_from("<I", data, eocd + 12)
    struct.pack_into("<I", data, eocd + 12, cd_size + len(extra))
    with (
        pytest.raises(CorruptionError) as caught,
        archivey.open_archive(_pipe(bytes(data)), streaming=True) as reader,
    ):
        for _ in reader.stream_members():
            pass
    assert str(1 << 63) in str(caught.value)


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        ("cd_size", "Bad offset for central directory"),
        ("locator", "Corrupt ZIP64 end of central directory locator"),
    ],
)
def test_a_damaged_end_record_fails_in_the_file_reads_words(
    edit: str, message: str
) -> None:
    """Only a missing end record is described from the bytes after the members; any
    other fault is the record's, said as a file read says it."""
    data = bytearray(_zip([("a.txt", b"one"), ("b.txt", b"two")]))
    eocd = data.rindex(b"PK\x05\x06")
    if edit == "cd_size":
        struct.pack_into("<I", data, eocd + 12, 0xFFFF_FF00)
    else:
        # Saturated, so the classic record cannot stand in for the ZIP64 records.
        struct.pack_into("<HH", data, eocd + 8, 0xFFFF, 0xFFFF)
        data[eocd:eocd] = struct.pack("<4sIQI", b"PK\x06\x07", 0, 1 << 40, 1)
    with pytest.raises(CorruptionError, match=message) as from_file:
        _seekable_view(bytes(data))
    with pytest.raises(CorruptionError, match=message) as from_pipe:
        _piped_view(bytes(data))
    assert type(from_pipe.value) is type(from_file.value)


def test_a_digital_signature_record_is_refused_as_from_a_file() -> None:
    """A digital signature record (APPNOTE 4.3.13) between the directory and the end
    record is counted as the directory's, which moves it off its entries; stdlib
    ``zipfile`` and the file read refuse the archive, and so does the pass."""
    data = bytearray(_zip([("a.txt", b"one"), ("b.txt", b"two")]))
    eocd = data.rindex(b"PK\x05\x06")
    data[eocd:eocd] = b"PK\x05\x05" + struct.pack("<H", 5) + b"sig!!"
    with pytest.raises(zipfile.BadZipFile, match="Bad magic number"):
        zipfile.ZipFile(io.BytesIO(bytes(data)))
    with pytest.raises(CorruptionError, match="Bad magic number"):
        _seekable_view(bytes(data))
    with pytest.raises(CorruptionError, match="Bad magic number"):
        _piped_view(bytes(data))


def _bit3_deflate_zip(
    members: list[tuple[str, bytes, bytes]], methods: dict[str, int] | None = None
) -> bytes:
    """A ZIP of bit-3 members, each ``(name, compressed, content)``, as a writer to
    a pipe lays it out: zero sizes in the local header, a signed data descriptor
    after the data. DEFLATE unless ``methods`` names another method for a member."""
    out = bytearray()
    central = bytearray()
    for name, deflated, content in members:
        method = (methods or {}).get(name, 8)
        offset = len(out)
        crc = zlib.crc32(content)
        encoded = name.encode()
        out += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0x08, method, 0, 0, 0, 0, 0, len(encoded), 0
        )
        out += encoded + deflated
        out += struct.pack("<IIII", 0x08074B50, crc, len(deflated), len(content))
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50, 20, 20, 0x08, method, 0, 0, crc, len(deflated), len(content),
            len(encoded), 0, 0, 0, 0, 0, offset,
        )  # fmt: skip
        central += encoded
    end = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, len(members), len(members), len(central),
        len(out), 0,
    )  # fmt: skip
    return bytes(out + central + end)


def _late_decode_failure_zip(size: int = 1_500_000) -> bytes:
    """Two bit-3 DEFLATE members; the first's stream turns invalid (a block of
    type 3) at the end of ``size`` random letters."""
    content = bytes(random.Random(0).choices(b"abcdefgh", k=size))
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    deflated = compressor.compress(content) + compressor.flush(zlib.Z_FULL_FLUSH)
    deflated += b"\x07"  # BFINAL set, BTYPE 11: no such block type
    second = zlib.compressobj(9, zlib.DEFLATED, -15)
    tail = second.compress(b"after") + second.flush()
    return _bit3_deflate_zip([("a.bin", deflated, content), ("b.txt", tail, b"after")])


def _pipe_reads(data: bytes) -> dict[str, object]:
    seen: dict[str, object] = {}
    with archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        try:
            for member, stream in reader.stream_members():
                assert stream is not None
                try:
                    seen[member.name] = stream.read()
                except CorruptionError as exc:
                    seen[member.name] = type(exc)
        except CorruptionError as exc:
            seen["<pass ended>"] = type(exc)
    return seen


def test_the_walk_scans_past_a_bit3_member_whose_decode_fails() -> None:
    """The decode fails far into the member; the scan finds its descriptor on the
    stored bytes, which needs no key, so the next member reads as from a file."""
    data = _late_decode_failure_zip()
    with archivey.open_archive(io.BytesIO(data)) as reader:
        assert reader.read("b.txt") == b"after"
    seen = _pipe_reads(data)
    assert seen["a.bin"] is CorruptionError
    assert seen["b.txt"] == b"after"


def test_the_walk_scans_past_a_failed_decode_longer_than_what_it_keeps() -> None:
    """Over 4 MiB of stored bytes before the decode fails, more than the walk keeps
    of what a read took: the scan starts at the kept bytes, and the next member
    still reads as from a file."""
    data = _late_decode_failure_zip(12_000_000)
    stored = zipfile.ZipFile(io.BytesIO(data)).getinfo("a.bin").compress_size
    # Past the window: the kept bytes plus the newest read.
    assert stored > zip_local_walk._CODEC_RETAIN + zip_local_walk._READ_CHUNK
    seen = _pipe_reads(data)
    assert seen["a.bin"] is CorruptionError
    assert seen["b.txt"] == b"after"


def test_a_bit3_ppmd_member_with_no_end_mark_fails_as_from_a_file() -> None:
    """PPMd has no flag for a missing end mark, so its decode fails as a file
    read's does, and the walk's scan passes the member."""
    pyppmd = importorskip("pyppmd")

    content = b"ppmd without its end mark\n" * 40
    encoder = pyppmd.Ppmd8Encoder(6, 16 << 20, 0)
    # Order 6, 16 MiB, restore method 0; flush(False) leaves out the end mark.
    body = struct.pack("<H", 5 | (15 << 4)) + encoder.encode(content)
    body += encoder.flush(False)
    second = zlib.compressobj(9, zlib.DEFLATED, -15)
    tail = second.compress(b"after") + second.flush()
    data = _bit3_deflate_zip(
        [("p.bin", body, content), ("b.txt", tail, b"after")], methods={"p.bin": 98}
    )
    with archivey.open_archive(io.BytesIO(data)) as reader:
        with pytest.raises(CorruptionError):
            reader.read("p.bin")
        assert reader.read("b.txt") == b"after"
    seen = _pipe_reads(data)
    assert seen["p.bin"] is CorruptionError
    assert seen["b.txt"] == b"after"


@pytest.mark.parametrize("read", [True, False], ids=["read", "skipped"])
@pytest.mark.parametrize(
    "method", [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED], ids=["deflate", "stored"]
)
def test_many_small_bit3_members_pass_about_their_own_bytes(
    method: int, read: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bit-3 member's end is found only by reading past it, and the walk puts
    back what it read too far for the next header. Each member reads ahead about
    its own length, not a whole read size: a thousand tiny members pass a few times
    the archive's bytes through the walk's source, not a read size each."""
    out = _Writer()
    with zipfile.ZipFile(out, "w", method) as zf:
        for i in range(1000):
            zf.writestr(f"f{i:04}.txt", f"member {i}\n" * 3)
    data = bytes(out.data)
    passed = _count_source_reads(monkeypatch)
    seen = 0
    with archivey.open_archive(_pipe(data), streaming=True) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            if read:
                assert stream.read() == f"member {int(member.name[1:5])}\n".encode() * 3
            seen += 1
    assert seen == 1000
    assert passed["bytes"] <= 4 * len(data)


def test_a_large_bit3_member_reads_ahead_in_growing_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The read ahead into a bit-3 member doubles with each full step, so a large
    member takes tens of reads from the walk's source, not one per first step."""
    content = random.Random(0).randbytes(5 << 20)
    out = _Writer()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.bin", content)
    passed = _count_source_reads(monkeypatch)
    with archivey.open_archive(_pipe(bytes(out.data)), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read() == content
    assert passed["calls"] < 1000


def test_a_bit3_stored_member_from_a_pipe_reads_full_counts() -> None:
    """``read(n)`` returns ``n`` bytes until the member's end, however small the
    steps the walk reads ahead in: a short read means the data ended."""
    content = random.Random(1).randbytes(100_000)
    out = _Writer()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("a.bin", content)
    with archivey.open_archive(_pipe(bytes(out.data)), streaming=True) as reader:
        for _member, stream in reader.stream_members():
            assert stream is not None
            chunks = []
            while chunk := stream.read(8192):
                chunks.append(chunk)
    assert [len(chunk) for chunk in chunks[:-1]] == [8192] * (len(chunks) - 1)
    assert b"".join(chunks) == content


@pytest.mark.parametrize("junk", [300, 2_000, 20_000, 60_000])
def test_junk_before_a_small_codec_members_descriptor_is_searched(junk: int) -> None:
    """Junk between a bit-3 codec member's end and its descriptor counts into the
    member (the file read refuses it). The descriptor search covers at least
    ``_DESCRIPTOR_SEARCH_PAST`` bytes past what the codec was handed, so how much
    junk is passed over does not depend on how small the member is."""
    assert junk + 100 < zip_local_walk._DESCRIPTOR_SEARCH_PAST
    content = b"a small member before junk\n" * 2
    first = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = first.compress(content) + first.flush() + b"\x01" * junk
    second = zlib.compressobj(9, zlib.DEFLATED, -15)
    tail = second.compress(b"after") + second.flush()
    data = _bit3_deflate_zip([("a.txt", body, content), ("b.txt", tail, b"after")])
    assert _pipe_reads(data) == {"a.txt": content, "b.txt": b"after"}


def _count_source_reads(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Count the calls to the walk's source and the bytes they return."""
    passed = {"bytes": 0, "calls": 0}
    source_read = zip_local_walk.ForwardSource.read

    def counting_read(self: zip_local_walk.ForwardSource, n: int) -> bytes:
        chunk = source_read(self, n)
        passed["bytes"] += len(chunk)
        passed["calls"] += 1
        return chunk

    monkeypatch.setattr(zip_local_walk.ForwardSource, "read", counting_read)
    return passed


def test_a_bit3_codec_stream_that_runs_into_its_descriptor_reads_only_from_a_pipe() -> (
    None
):
    """A recorded difference (``dev-docs/formats/zip.md`` §2.2.2). The deflate
    stream's last byte is the ``P`` of the descriptor's signature, so the codec needs
    one byte more than the compressed size the descriptor and the directory state.
    A file read bounds the stream at that size and raises ``TruncatedError``. The
    pass does not know where the codec ended; it finds the descriptor by the decoded
    CRC and size, and serves the data, which that CRC verifies.

    The checks on the fixture itself (``check.eof`` and ``check.unused_data``) are
    what prove the stream needs exactly one byte past the stated size: without them
    the two reads could differ for another reason and the test would still pass."""
    content = b"xyz" * 200
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    stream = compressor.compress(content) + compressor.flush()
    check = zlib.decompressobj(-15)
    assert check.decompress(stream[:-1] + b"PK\x07\x08") == content
    assert check.eof
    assert check.unused_data == b"K\x07\x08"
    tail = zlib.compressobj(9, zlib.DEFLATED, -15)
    after = tail.compress(b"after") + tail.flush()
    data = _bit3_deflate_zip(
        [("a.txt", stream[:-1], content), ("b.txt", after, b"after")]
    )
    with archivey.open_archive(io.BytesIO(data)) as reader:
        with pytest.raises(TruncatedError):
            reader.read("a.txt")
        assert reader.read("b.txt") == b"after"
    assert _pipe_reads(data) == {"a.txt": content, "b.txt": b"after"}


def _zeros_bit3_zip(size: int, method: int) -> bytes:
    """A bit-3 member ``bomb.bin`` of ``size`` zero bytes under ``method`` (DEFLATE
    or bzip2), then a short bit-3 DEFLATE member ``b.txt``."""
    if method == 12:
        compressor = bz2.BZ2Compressor(9)
        packed = compressor.compress(bytes(size)) + compressor.flush()
    else:
        deflate = zlib.compressobj(9, zlib.DEFLATED, -15)
        packed = deflate.compress(bytes(size)) + deflate.flush()
    second = zlib.compressobj(9, zlib.DEFLATED, -15)
    tail = second.compress(b"after") + second.flush()
    return _bit3_deflate_zip(
        [("bomb.bin", packed, bytes(size)), ("b.txt", tail, b"after")],
        methods={"bomb.bin": method},
    )


@pytest.mark.parametrize("method", [8, 12], ids=["deflate", "bzip2"])
@pytest.mark.parametrize("read_first", [None, 10], ids=["unread", "read-10"])
def test_the_pass_decodes_a_bit3_member_it_reads_past_only_as_far_as_a_link_needs(
    monkeypatch: pytest.MonkeyPatch, method: int, read_first: int | None
) -> None:
    """Its codec finds a bit-3 member's end only by decoding all of it, which no limit
    bounds: a bzip2 member of a few hundred bytes decodes to a gigabyte. The pass
    decodes what tells a link target or a reparse buffer's start, whether or not the
    caller began a read, and the walk's scan finds where the rest ends, as for an
    encrypted member nobody read. The listing is a file read's."""
    size = 16 << 20
    data = _zeros_bit3_zip(size, method)
    decoded: dict[str, int] = {}
    read_chunk = zip_forward_reader._PassData._read_chunk

    def counting(self: zip_forward_reader._PassData, n: int) -> bytes:
        chunk = read_chunk(self, n)
        decoded[self.member.name] = decoded.get(self.member.name, 0) + len(chunk)
        return chunk

    monkeypatch.setattr(zip_forward_reader._PassData, "_read_chunk", counting)
    with archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            if member.name == "b.txt":
                assert stream.read() == b"after"
            elif read_first is not None:
                assert stream.read(read_first) == bytes(read_first)
        listing = reader.members_report().members
    # The byte past the target cap, and the start of a reparse buffer after it.
    assert decoded["bomb.bin"] <= MAX_LINK_TARGET_BYTES + 1 + _MAX_REPARSE_PREFIX
    with archivey.open_archive(io.BytesIO(data)) as reader:
        from_file = reader.members()
    assert [_visible(m) for m in listing] == [_visible(m) for m in from_file]
    assert listing[0].size == size


def test_a_descriptor_planted_in_a_bit3_member_nobody_read_fails_it() -> None:
    """The scan matches a descriptor on its size and the signature after it, as on
    ciphertext: one planted in a DEFLATE stored block ends the member early, and the
    directory catches it at the end of the pass (DR-5a). Read to its end, the codec
    finds the real end, as from a file."""
    prefix = b"x" * 100
    # The stored block's 5-byte header comes before the prefix.
    planted = struct.pack("<IIII", 0x08074B50, 0, 5 + len(prefix), len(prefix))
    content = prefix + planted + b"PK\x03\x04" + bytes(26) + b"y" * 10_000
    deflate = zlib.compressobj(0, zlib.DEFLATED, -15)
    packed = deflate.compress(content) + deflate.flush()
    assert packed[5 : 5 + len(prefix)] == prefix
    second = zlib.compressobj(9, zlib.DEFLATED, -15)
    tail = second.compress(b"after") + second.flush()
    data = _bit3_deflate_zip([("a.bin", packed, content), ("b.txt", tail, b"after")])
    from_file, _ = _seekable_view(data, read=False)
    assert [m["name"] for m in from_file] == ["a.bin", "b.txt"]
    assert _pipe_reads(data) == {"a.bin": content, "b.txt": b"after"}
    with (
        archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as reader,
        pytest.raises(CorruptionError, match="data descriptor after its data"),
    ):
        for _ in reader.stream_members():
            pass


@pytest.mark.parametrize("read", [True, False], ids=["read", "unread"])
def test_a_bit3_link_the_pass_reads_past_keeps_its_target(read: bool) -> None:
    """Data within the target cap is decoded to its end and checked: the codec ends
    within what the pass decodes to tell a link target."""
    data = _streamed(_symlink_zip())
    with archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        for _, stream in reader.stream_members():
            if read and stream is not None:
                stream.read()
        members = {m.name: m for m in reader.members_report().members}
    assert members["link"].type is MemberType.SYMLINK
    assert members["link"].link_target == "a.txt"
