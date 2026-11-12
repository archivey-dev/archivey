"""ARJ archives (``ContainerFormat.ARJ``).

The fixtures in ``tests/fixtures/external/arj_310`` were written by ARJ 3.10 for Linux
(``arj`` in Debian and Ubuntu), plus two of Commons Compress's archives, one from ARJ
for DOS. The damaged archives come from :func:`_archive`, a test-only writer of stored
members.
"""

from __future__ import annotations

import hashlib
import io
import struct
import zlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from archivey import (
    ArchiveFormat,
    CompressionAlgorithm,
    CreateSystem,
    MemberType,
    detect_format,
    open_archive,
)
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    CorruptionError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
)
from tests.pe_build import elf_file, pe_file
from tests.streams_util import NonSeekableBytesIO, ShortReadBytesIO

_FIXTURES = Path(__file__).parent / "fixtures" / "external" / "arj_310"

# The files the ARJ 3.10 fixtures hold: (size, SHA-256).
_CONTENTS = {
    "words.txt": (
        15_995,
        "1d653119304bf9bfc381f8ec11bcbeb298744d27c1ce7f44a916815082d2d82d",
    ),
    "runs.bin": (
        37_353,
        "f2e85b931ab8960e45f84f4e12a404cf8c28c38eda3f55176a0e2471ccd5df31",
    ),
    "small.txt": (
        10,
        "8987a3f53737783a18f86ec5f268a51549bb0d677384bb8442eac2fdb178877e",
    ),
    "empty": (0, hashlib.sha256(b"").hexdigest()),
}


def _read_all(path: Path | io.BytesIO) -> dict[str, bytes]:
    with open_archive(path) as reader:
        return {
            member.name: stream.read() if stream is not None else b""
            for member, stream in reader.stream_members()
        }


@pytest.mark.parametrize("method", [1, 2, 3, 4])
def test_each_method_decodes(method: int) -> None:
    path = _FIXTURES / f"method{method}.arj"
    with open_archive(path) as reader:
        assert reader.format == ArchiveFormat.ARJ
        members = {m.name: m for m in reader.members()}
        for name, member in members.items():
            data = reader.read(member)
            size, digest = _CONTENTS[name]
            assert (len(data), hashlib.sha256(data).hexdigest()) == (size, digest)
            assert member.extra["arj.method"] in (0, method)
            assert member.create_system is CreateSystem.UNIX
            assert member.mode == 0o644
        words = members["words.txt"]
        expected = (
            CompressionAlgorithm.ARJ_FAST if method == 4 else CompressionAlgorithm.LZH
        )
        assert words.compression[0].algo is expected
        # ARJ for Unix stores Unix times.
        assert words.modified is not None
        assert words.modified.tzinfo is not None
        assert words.modified.year == 2026


def test_small_reads_and_a_seek_inside_a_member() -> None:
    with open_archive(_FIXTURES / "method1.arj") as reader:
        member = reader.get("runs.bin")
        with reader.open(member) as stream:
            parts = []
            while chunk := stream.read(997):
                parts.append(chunk)
        whole = b"".join(parts)
        assert hashlib.sha256(whole).hexdigest() == _CONTENTS["runs.bin"][1]


def test_unix_links_and_special_files() -> None:
    with open_archive(_FIXTURES / "links.arj") as reader:
        members = {m.name: m for m in reader.members()}
    assert members["link"].type is MemberType.SYMLINK
    assert members["link"].link_target == "small.txt"
    # ARJ stores the data once, under the first name, and the later one as a link.
    assert members["small.txt"].type is MemberType.FILE
    assert members["hard.txt"].type is MemberType.HARDLINK
    assert members["hard.txt"].link_target == "small.txt"
    assert members["fifo"].type is MemberType.OTHER
    assert members["fifo"].extra["special_file_type"] == "fifo"
    assert members["dir/sub/"].type is MemberType.DIRECTORY


def test_links_extract(tmp_path: Path) -> None:
    with open_archive(_FIXTURES / "links.arj") as reader:
        # The archive holds a FIFO, which extraction refuses; the rest is written.
        reader.extract_all(tmp_path, on_blocked="skip")
    assert (tmp_path / "small.txt").read_bytes() == b"hello arj\n"
    assert (tmp_path / "hard.txt").read_bytes() == b"hello arj\n"
    assert (tmp_path / "link").is_symlink()
    assert (tmp_path / "dir" / "sub").is_dir()


@pytest.mark.parametrize(
    ("name", "system", "hour"),
    [
        # ARJ for Windows (host 11) stores a DOS time (local time, read as is); ARJ
        # for Unix a Unix time. Commons Compress's two archives hold the same files.
        ("cc_bla_dos.arj", CreateSystem.WINDOWS_NTFS, 23),
        ("cc_bla_unix.arj", CreateSystem.UNIX, 21),
    ],
)
def test_commons_compress_archives(name: str, system: CreateSystem, hour: int) -> None:
    with open_archive(_FIXTURES / name) as reader:
        members = reader.members()
        assert [m.name for m in members] == ["test1.xml", "test2.xml"]
        for member in members:
            assert member.create_system is system
            assert member.modified is not None
            assert member.modified.hour == hour
            assert reader.read(member).startswith(b"<?xml")


def test_a_garbled_member_is_listed_and_refused() -> None:
    with open_archive(_FIXTURES / "garbled.arj") as reader:
        (member,) = reader.members()
        assert member.is_encrypted
        with pytest.raises(UnsupportedFeatureError, match="garbled"):
            reader.read(member)


def test_detection_by_content() -> None:
    data = (_FIXTURES / "method1.arj").read_bytes()
    assert detect_format(io.BytesIO(data)).format == ArchiveFormat.ARJ
    # Anything else that starts with the two magic bytes fails at open.
    with pytest.raises(CorruptionError):
        open_archive(io.BytesIO(b"\x60\xea" + bytes(60)))


def test_a_pipe_is_refused() -> None:
    data = (_FIXTURES / "stored.arj").read_bytes()
    with pytest.raises(StreamNotSeekableError):
        open_archive(NonSeekableBytesIO(data), format=ArchiveFormat.ARJ)


# --- damaged archives, from a test-only writer --------------------------------------


def _block(body: bytes) -> bytes:
    return struct.pack("<H", len(body)) + body + struct.pack("<I", zlib.crc32(body))


def _header(
    name: bytes,
    *,
    file_type: int,
    method: int = 0,
    flags: int = 0,
    stored: int = 0,
    size: int = 0,
    crc: int = 0,
    extended: tuple[bytes, ...] = (),
    host: int = 0,  # MS-DOS
    modified: int = 0x5A6E_5000,  # a DOS time in 2025
    mode: int = 0x20,
) -> bytes:
    fixed = struct.pack(
        "<BBBBBBBBIIIIHHBB",
        30,
        11,
        1,
        host,
        flags,
        method,
        file_type,
        0,
        modified,
        stored,
        size,
        crc,
        0,
        mode,
        0,
        0,
    )
    out = b"\x60\xea" + _block(fixed + name + b"\0" + b"\0")
    for ext in extended:
        out += _block(ext)
    return out + b"\0\0"


def _archive(*members: tuple[bytes, bytes], tail: bytes = b"", **options: int) -> bytes:
    """An ARJ archive of stored members (name, data), from MS-DOS."""
    out = _header(b"test.arj", file_type=2)
    for name, data in members:
        out += _header(
            name,
            file_type=0,
            stored=len(data),
            size=len(data),
            crc=zlib.crc32(data),
            **options,
        )
        out += data
    return out + b"\x60\xea\0\0" + tail


def test_the_writer_makes_a_readable_archive() -> None:
    data = _archive((b"a.txt", b"alpha"), (b"dir\\b.txt", b"beta"))
    assert _read_all(io.BytesIO(data)) == {"a.txt": b"alpha", "dir/b.txt": b"beta"}
    with open_archive(io.BytesIO(data)) as reader:
        member = reader.get("a.txt")
        assert member.modified == datetime(2025, 3, 14, 10, 0, 0)
        assert member.mode is None
        assert member.windows_attrs == 0x20


def test_a_header_crc_failure_is_corruption() -> None:
    data = bytearray(_archive((b"a.txt", b"alpha")))
    first = data.index(b"a.txt")
    data[first] ^= 1
    with pytest.raises(CorruptionError, match="fails its CRC"):
        _read_all(io.BytesIO(bytes(data)))


def test_a_data_crc_failure_is_corruption() -> None:
    data = _archive((b"a.txt", b"alpha"))
    with pytest.raises(CorruptionError):
        _read_all(io.BytesIO(data.replace(b"alpha", b"alphb")))


def test_a_compressed_member_that_is_damaged_or_cut() -> None:
    data = bytearray((_FIXTURES / "method1.arj").read_bytes())
    data[400] ^= 0xFF
    with pytest.raises(CorruptionError):
        _read_all(io.BytesIO(bytes(data)))
    cut = (_FIXTURES / "method4.arj").read_bytes()[:3000]
    with pytest.raises(TruncatedError):
        _read_all(io.BytesIO(cut))


def test_a_missing_header_is_corruption() -> None:
    data = _archive((b"a.txt", b"alpha"))
    end = data.rindex(b"\x60\xea\0\0")
    with pytest.raises(CorruptionError, match="no header"):
        _read_all(io.BytesIO(data[:end] + b"junk" + data[end:]))


def test_an_oversized_header_is_corruption() -> None:
    data = bytearray(_archive((b"a.txt", b"alpha")))
    second = data.index(b"\x60\xea", 2)
    struct.pack_into("<H", data, second + 2, 3000)
    with pytest.raises(CorruptionError, match="size 3000"):
        _read_all(io.BytesIO(bytes(data)))


def test_a_second_main_header_is_corruption() -> None:
    data = _archive()
    main = data[: data.rindex(b"\x60\xea\0\0")]
    with pytest.raises(CorruptionError, match="second main header"):
        _read_all(io.BytesIO(main + main + b"\x60\xea\0\0"))


@pytest.mark.parametrize(
    "wrap", [io.BytesIO, ShortReadBytesIO], ids=["sized", "size-unknown"]
)
def test_an_archive_cut_inside_a_member_is_truncated(wrap) -> None:
    # ShortReadBytesIO is a stream archivey cannot size cheaply, so the reader has to
    # ask the source whether the member's last byte is there. A compressed member
    # shows it: without that check the decoder meets the cut first and calls it damage.
    data = _archive((b"a.txt", b"alpha" * 100), method=1)
    with pytest.raises(TruncatedError):
        _read_all(wrap(data[:-200]))


@pytest.mark.parametrize("flags", [0x04, 0x08], ids=["continues", "continued"])
def test_a_member_split_across_volumes_is_refused(flags: int) -> None:
    data = _archive((b"a.txt", b"alpha"), flags=flags)
    with (
        open_archive(io.BytesIO(data)) as reader,
        pytest.raises(UnsupportedFeatureError, match="split across ARJ volumes"),
    ):
        reader.read(reader.get("a.txt"))


def test_an_unknown_method_is_listed_and_refused() -> None:
    data = _archive((b"a.txt", b"alpha"), method=9)
    with open_archive(io.BytesIO(data)) as reader:
        member = reader.get("a.txt")
        assert member.compression[0].algo is CompressionAlgorithm.UNKNOWN
        with pytest.raises(UnsupportedFeatureError, match="ARJ method 9"):
            reader.read(member)


def test_data_after_the_end_header_is_reported() -> None:
    data = _archive((b"a.txt", b"alpha"), tail=b"\0\0garbage")
    with open_archive(io.BytesIO(data)) as reader:
        reader.members()
        (diagnostic,) = reader.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
    assert diagnostic.context.observed_bytes == 2


def test_zero_padding_after_the_end_header_is_not_reported() -> None:
    data = _archive((b"a.txt", b"alpha"), tail=b"\0\0\x1a")
    with open_archive(io.BytesIO(data)) as reader:
        reader.members()
        assert not reader.diagnostics.retained


def test_a_unix_special_header_cut_short_is_corruption() -> None:
    out = _header(b"test.arj", file_type=2)
    # A symlink header that says its target is 5 bytes but holds 2.
    out += _header(b"link", file_type=6, extended=(b"U\x00" + bytes([0x45]) + b"ab",))
    out += b"\x60\xea\0\0"
    with pytest.raises(CorruptionError, match="cut short"):
        _read_all(io.BytesIO(out))


def test_utc_times_for_a_unix_host() -> None:
    with open_archive(_FIXTURES / "links.arj") as reader:
        member = reader.get("small.txt")
    assert member.modified is not None
    assert member.modified.tzinfo == UTC


def test_a_missing_end_header_is_reported() -> None:
    data = _archive((b"a.txt", b"alpha"))
    with open_archive(io.BytesIO(data[:-4])) as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]
        (diagnostic,) = reader.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_EOF_MARKER_MISSING
    assert diagnostic.context.expected_marker == "end_of_archive_header"


def test_a_dos_name_splits_on_backslash_after_decoding() -> None:
    # In cp932 the second byte of 表 is 0x5C, the byte of "\": a replace on the bytes
    # would split the character.
    stored = "表\\a.txt".encode("cp932")
    data = _archive((stored, b"alpha"))
    with open_archive(io.BytesIO(data), encoding="cp932") as reader:
        (member,) = reader.members()
    assert member.name == "表/a.txt"
    assert member.raw_name == stored


def _raw_header(body: bytes) -> bytes:
    return b"\x60\xea" + _block(body) + b"\0\0"


def _fixed(first: int = 30) -> bytes:
    fixed = bytearray(_header(b"a", file_type=0)[4 : 4 + 30])
    fixed[0] = first
    return bytes(fixed)


def test_a_name_with_no_end_is_corruption() -> None:
    data = _header(b"test.arj", file_type=2) + _raw_header(_fixed() + b"a.txt")
    with pytest.raises(CorruptionError, match="has no end"):
        _read_all(io.BytesIO(data + b"\x60\xea\0\0"))


def test_a_fixed_part_size_out_of_range_is_corruption() -> None:
    body = _fixed(first=29) + b"\0" * 10
    data = _header(b"test.arj", file_type=2) + _raw_header(body)
    with pytest.raises(CorruptionError, match="fixed part of 29 bytes"):
        _read_all(io.BytesIO(data + b"\x60\xea\0\0"))


def test_an_extended_header_crc_failure_is_corruption() -> None:
    member = bytearray(_header(b"a.txt", file_type=0, extended=(b"Xdata",)))
    member[-3] ^= 1  # the extended header's CRC, before the closing 0 length
    data = _header(b"test.arj", file_type=2) + bytes(member) + b"\x60\xea\0\0"
    with pytest.raises(CorruptionError, match="extended header .* fails its CRC"):
        _read_all(io.BytesIO(data))


def test_a_unix_special_header_with_a_two_byte_length() -> None:
    target = b"t" * 40
    ext = b"U\x00" + bytes([(2 << 5) | 0x1F]) + struct.pack("<H", len(target)) + target
    out = _header(b"test.arj", file_type=2)
    out += _header(b"link", file_type=6, extended=(ext,)) + b"\x60\xea\0\0"
    with open_archive(io.BytesIO(out)) as reader:
        (member,) = reader.members()
    assert member.type is MemberType.SYMLINK
    assert member.link_target == "t" * 40


# --- method 4 on hand-built bit streams ----------------------------------------------


def _bits(*fields: str) -> bytes:
    """Bits written most significant first, zero-padded to whole bytes."""
    text = "".join(fields)
    text += "0" * (-len(text) % 8)
    return int(text, 2).to_bytes(len(text) // 8, "big") if text else b""


def _fast(stream: bytes, size: int) -> bytes:
    from archivey.internal.streams.codecs.arj_fast_decoder import ArjFastDecoder

    parts = [stream]
    decoder = ArjFastDecoder(size, lambda: parts.pop() if parts else None)
    out = b""
    while chunk := decoder.read(1 << 16):
        out += chunk
    return out


# A literal: length code "0", then 8 bits. A match of 3 bytes: length code "100"
# (width 1, value 1); distance less one 0: "0" then 9 bits.
_LITERAL_A = ("0", format(ord("a"), "08b"))
_MATCH_3_BACK_1 = ("100", "0", "0" * 9)


def test_method4_literal_and_match() -> None:
    assert _fast(_bits(*_LITERAL_A, *_MATCH_3_BACK_1), 4) == b"aaaa"


def test_method4_last_match_is_cut_at_the_size() -> None:
    assert _fast(_bits(*_LITERAL_A, *_MATCH_3_BACK_1), 3) == b"aaa"


def test_method4_match_before_the_output_is_corruption() -> None:
    with pytest.raises(CorruptionError, match="before the start of the output"):
        _fast(_bits(*_MATCH_3_BACK_1), 3)


# --- shared member fields ------------------------------------------------------------


def _one(*headers: bytes) -> list:
    out = _header(b"test.arj", file_type=2) + b"".join(headers) + b"\x60\xea\0\0"
    with open_archive(io.BytesIO(out)) as reader:
        members = reader.members()
        codes = [d.code for d in reader.diagnostics.retained]
        reads = [reader.read(m) if m.size is not None else None for m in members]
    return [members, codes, reads]


@pytest.mark.parametrize(
    ("kind", "expected"),
    [(0, "fifo"), (3, "char_device"), (4, "block_device"), (5, "unknown")],
)
def test_a_unix_special_uses_the_shared_type_names(kind: int, expected: str) -> None:
    ext = b"U\x00" + bytes([kind << 5])
    (members, _codes, _reads) = _one(_header(b"dev", file_type=6, extended=(ext,)))
    assert members[0].type is MemberType.OTHER
    assert members[0].extra["special_file_type"] == expected


def test_a_directory_that_declares_data_keeps_it_and_says_so() -> None:
    body = b"SECRET"
    header = _header(
        b"dir",
        file_type=3,
        stored=len(body),
        size=len(body),
        crc=zlib.crc32(body),
    )
    (members, codes, reads) = _one(header + body)
    assert members[0].type is MemberType.DIRECTORY
    assert members[0].size == len(body)
    assert codes == [DiagnosticCode.MEMBER_DIRECTORY_DATA_IGNORED]
    assert reads == [body]


def test_the_header_crc_is_a_stored_digest() -> None:
    from archivey import HashAlgorithm

    data = _archive((b"a.txt", b"alpha"))
    with open_archive(io.BytesIO(data)) as reader:
        member = reader.get("a.txt")
        assert member.hashes[HashAlgorithm.CRC32] == zlib.crc32(b"alpha").to_bytes(
            4, "big"
        )


def test_the_listing_is_a_header_walk() -> None:
    from archivey import ListingCost

    with open_archive(_FIXTURES / "method1.arj") as reader:
        assert reader.cost.listing_cost is ListingCost.REQUIRES_SCANNING


def test_a_unix_time_of_zero_is_the_epoch() -> None:
    header = _header(b"a", file_type=0, host=2, modified=0)
    (members, _codes, _reads) = _one(header)
    assert members[0].modified == datetime(1970, 1, 1, tzinfo=UTC)


@pytest.mark.parametrize(
    ("host", "system"),
    [(10, CreateSystem.VFAT), (11, CreateSystem.WINDOWS_NTFS)],
)
def test_windows_hosts(host: int, system: CreateSystem) -> None:
    (members, _codes, _reads) = _one(_header(b"a", file_type=0, host=host))
    assert members[0].create_system is system


def test_a_garbled_flag_marks_any_member_encrypted() -> None:
    (members, _codes, _reads) = _one(_header(b"d", file_type=3, flags=0x01))
    assert members[0].is_encrypted


# --- self-extracting archives -------------------------------------------------------


def test_a_self_extractor_from_arj_for_unix() -> None:
    # ``arj a -je1``: ARJ's ARJSFXJR stub, an ELF program, then the archive.
    path = _FIXTURES / "sfx_junior"
    info = detect_format(path)
    assert info.format == ArchiveFormat.ARJ
    assert info.payload_offset == 23_104
    for fmt in (None, ArchiveFormat.ARJ):
        with open_archive(path, format=fmt) as reader:
            (member,) = reader.members()
            data = reader.read(member)
            assert not reader.diagnostics.retained
        assert member.name == "small.txt"
        assert hashlib.sha256(data).hexdigest() == _CONTENTS["small.txt"][1]


def _decoys() -> bytes:
    # Stub code with the two magic bytes in it, as any stub has: once bare, once with
    # a size the header allows but no CRC to match, once with the main header's bytes
    # behind a CRC that fails, and once as a whole member header, whose CRC holds but
    # whose file type is not the main header's.
    main = _header(b"test.arj", file_type=2)
    broken = main[:-8] + bytes([main[-8] ^ 1]) + main[-7:]
    member = _header(b"x", file_type=0)
    return b"\x60\xea\x90\x90" + b"\x60\xea\x40\x00" + bytes(64) + broken + member


# Stubs: a DOS program (``MZ`` with no PE header, as ARJ's own DOS modules are), a PE,
# an ELF, and bytes with no executable cue, which detection scans last.
_STUBS = {
    "dos": b"MZ" + bytes(0x3E) + _decoys() + bytes(range(256)) * 4,
    "pe": pe_file(0x1000, payload=_decoys()),
    "elf": elf_file(0x1000, payload=_decoys()),
    "none": b"\xe9\x10\x02" + _decoys() + bytes(range(256)) * 4,
}


@pytest.mark.parametrize("stub", sorted(_STUBS))
@pytest.mark.parametrize("forced", [False, True], ids=["detected", "forced"])
def test_an_archive_behind_a_stub(stub: str, forced: bool) -> None:
    head = _STUBS[stub]
    data = head + _archive((b"a.txt", b"alpha"))
    if not forced:
        info = detect_format(io.BytesIO(data))
        assert info.format == ArchiveFormat.ARJ
        assert info.payload_offset == len(head)
    fmt = ArchiveFormat.ARJ if forced else None
    with open_archive(io.BytesIO(data), format=fmt) as reader:
        assert {m.name: reader.read(m) for m in reader.members()} == {"a.txt": b"alpha"}
        assert not reader.diagnostics.retained


def test_a_forced_open_of_a_file_with_no_archive_is_corruption() -> None:
    with pytest.raises(CorruptionError, match="Not an ARJ archive"):
        open_archive(io.BytesIO(b"MZ" + bytes(512)), format=ArchiveFormat.ARJ)
    # With only decoys, the scan falls back to the first, as the RAR and 7z scans do,
    # and the error names what is wrong there.
    with pytest.raises(CorruptionError, match="ARJ header"):
        open_archive(
            io.BytesIO(b"MZ" + _decoys() + bytes(512)), format=ArchiveFormat.ARJ
        )


def test_a_stub_cut_inside_the_main_header_is_truncated() -> None:
    main = _header(b"test.arj", file_type=2)
    data = b"MZ" + bytes(0x3E) + main[:20]
    with pytest.raises(TruncatedError):
        open_archive(io.BytesIO(data), format=ArchiveFormat.ARJ)


def _secured(envelope: bytes, *, at_end: bool = True) -> bytes:
    """An archive with an ARJ-SECURITY envelope after its end header, as a registered
    ARJ writes one: the main header's flag, the envelope's start in its size field and
    its length in its mode field."""
    member = _header(b"a.txt", file_type=0, stored=5, size=5, crc=zlib.crc32(b"alpha"))
    plain_main = _header(b"test.arj", file_type=2)
    end = len(plain_main) + len(member) + 5 + 4
    main = _header(
        b"test.arj",
        file_type=2,
        flags=0x40,
        size=end if at_end else end + 1,
        mode=len(envelope),
    )
    return main + member + b"alpha" + b"\x60\xea\0\0" + envelope


def test_a_security_envelope_after_the_end_header_is_not_trailing_data() -> None:
    data = _secured(bytes(8) + b"\xa5\x63" * 56)
    with open_archive(io.BytesIO(data)) as reader:
        assert [m.name for m in reader.members()] == ["a.txt"]
        assert not reader.diagnostics.retained


def test_data_after_a_security_envelope_is_reported() -> None:
    data = _secured(b"\xa5" * 16) + b"more"
    with open_archive(io.BytesIO(data)) as reader:
        reader.members()
        (diagnostic,) = reader.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA


def test_an_envelope_the_main_header_does_not_place_there_is_trailing_data() -> None:
    data = _secured(b"\xa5" * 16, at_end=False)
    with open_archive(io.BytesIO(data)) as reader:
        reader.members()
        (diagnostic,) = reader.diagnostics.retained
    assert diagnostic.code is DiagnosticCode.ARCHIVE_TRAILING_DATA
