"""Encrypted ZIP members read from a source that cannot seek, with one password, a
list of them or a provider.

The pass decrypts a member whose local header states its size, a bit-3 STORED one
(its end is found on the ciphertext) and a bit-3 codec one. A codec one the caller
reads is decoded to its end, and a missing or wrong password ends the walk there;
one nobody reads is scanned on the ciphertext, as a STORED one is, with no key.
Each read must give what the seekable read gives: the same bytes, or the same kind
of error.
"""

from __future__ import annotations

import io
import random
import struct
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

import archivey
from archivey.diagnostics import DiagnosticCode, EncryptedVerificationContext
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    EncryptionError,
    TruncatedError,
    UnsupportedFeatureError,
    raw_message_of,
)
from tests.conftest import importorskip, requires
from tests.streams_util import NonSeekableBytesIO
from tests.zip_descriptors import without_descriptor_signatures
from tests.zipcrypto import (
    build_zipcrypto_zip,
    corrupt_zipcrypto_payload,
)

_COLLISION = (
    Path(__file__).parent / "fixtures" / "zipcrypto" / "check_byte_collision.zip"
)
_PASSWORD = b"secret"
_TEXT = b"the quick brown fox jumps over the lazy dog\n" * 40


def _aes_zip(**kwargs: object) -> bytes:
    from tests.zip_aes_fixture import build_aes_zip

    return build_aes_zip([(b"a.txt", _TEXT)], password=_PASSWORD, **kwargs)  # type: ignore[arg-type]


def _with_plain_member(data: bytes) -> bytes:
    """``data`` with an unencrypted ``plain.txt`` after its members, so a test can
    see that the pass goes on past the encrypted one."""
    with zipfile.ZipFile(io.BytesIO(data)) as src:
        entries = src.infolist()
    eocd = data.rindex(b"PK\x05\x06")
    cd_size, cd_offset = struct.unpack_from("<II", data, eocd + 12)
    body = data[:cd_offset]
    directory = data[cd_offset : cd_offset + cd_size]
    name = b"plain.txt"
    payload = b"plain"
    crc = zlib.crc32(payload)
    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(name),
            0,
        )
        + name
        + payload
    )
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(payload),
            len(payload),
            len(name),
            0,
            0,
            0,
            0,
            0,
            len(body),
        )
        + name
    )
    count = len(entries) + 1
    directory += central
    end = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        count,
        count,
        len(directory),
        len(body) + len(local),
        0,
    )
    return body + local + directory + end


def _bit3_stored_zipcrypto(
    data: bytes, *, dos_time: int = 0x5A3C, stored: bytes | None = None
) -> bytes:
    """One STORED ZipCrypto member written as a pipe writer would: bit 3, zero sizes
    and CRC in the local header, a descriptor after the data. The check byte is then
    the DOS time's high byte. ``stored`` replaces the encrypted data."""
    from tests.zipcrypto import _encrypt

    name = b"a.txt"
    crc = zlib.crc32(data)
    enc = (
        _encrypt(_PASSWORD, (dos_time >> 8) & 0xFF, data) if stored is None else stored
    )
    flags = 0x1 | 0x8
    local = (
        struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, flags, 0, dos_time, 0, 0, 0, 0, len(name), 0
        )
        + name
        + enc
        + struct.pack("<IIII", 0x08074B50, crc, len(enc), len(data))
    )
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            flags,
            0,
            dos_time,
            0,
            crc,
            len(enc),
            len(data),
            len(name),
            0,
            0,
            0,
            0,
            0,
            0,
        )
        + name
    )
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def _shorter_than_its_header() -> bytes:
    """Four bytes of data with a matching descriptor: whole, and too short to hold
    a ZipCrypto header."""
    return _bit3_stored_zipcrypto(b"", stored=b"\x01\x02\x03\x04")


def _bit3_aes_stored_of_length(length: int) -> bytes:
    """A bit-3 STORED AES-256 member whose data is ``length`` bytes and a matching
    descriptor: whole, and too short for its salt, verifier and code."""
    name = b"a.txt"
    extra = struct.pack("<HHH2sBH", 0x9901, 7, 2, b"AE", 3, 0)
    stored = bytes(range(1, length + 1))
    flags = 0x1 | 0x8
    local = (
        struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 51, flags, 99, 0, 0, 0, 0, 0, len(name), 7 + 4
        )
        + name
        + extra
        + stored
        + struct.pack("<IIII", 0x08074B50, 0, len(stored), 0)
    )
    central = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            51,
            51,
            flags,
            99,
            0,
            0,
            0,
            len(stored),
            0,
            len(name),
            7 + 4,
            0,
            0,
            0,
            0,
            0,
        )
        + name
        + extra
    )
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


def _aes_shorter_than_its_header() -> bytes:
    return _bit3_aes_stored_of_length(4)


def _aes_shorter_than_its_code() -> bytes:
    """Past the salt and the verifier, short of the code: refused before the
    password is checked, as from a file."""
    return _bit3_aes_stored_of_length(20)


#: Whole members too short for their encryption: refused for that under a password.
_TOO_SHORT = (
    _shorter_than_its_header,
    _aes_shorter_than_its_header,
    _aes_shorter_than_its_code,
)


def _bit3_zipcrypto(compression: int) -> bytes:
    return _bit3(
        build_zipcrypto_zip(
            _PASSWORD, b"a.txt", _TEXT, compression=compression, check_byte=0
        )
    )


#: Past several of the decrypt stage's 64 KiB reads, and compressible only in part.
_LONG = random.Random(5).randbytes(100_000) + _TEXT * 100


def _deflate64(data: bytes) -> bytes:
    import inflate64

    deflater = inflate64.Deflater()
    return deflater.deflate(data) + deflater.flush()


def _ppmd(data: bytes) -> bytes:
    """ZIP method 98: the order and memory word, then PPMd8 with its end mark."""
    import pyppmd

    order, mem_mb = 6, 16
    encoder = pyppmd.Ppmd8Encoder(order, mem_mb << 20, 0)
    word = (order - 1) | ((mem_mb - 1) << 4)
    return struct.pack("<H", word) + encoder.encode(data) + encoder.flush(True)


def _aes_precompressed(method: int, encode, *, vendor_version: int) -> bytes:
    from tests.zip_aes_fixture import build_aes_zip

    return build_aes_zip(
        [(b"a.txt", _LONG)],
        password=_PASSWORD,
        method=method,
        encode=encode,
        vendor_version=vendor_version,
    )


def _zipcrypto_precompressed(method: int, encode, *, bit3: bool) -> bytes:
    """``_LONG`` under ZipCrypto, compressed with a codec stdlib cannot write: the two
    whose decoders cannot say how much of their last input they used."""
    data = build_zipcrypto_zip(
        _PASSWORD,
        b"a.txt",
        _LONG,
        compression=method,
        compressed=encode(_LONG),
        check_byte=0 if bit3 else None,
    )
    return _bit3(data) if bit3 else data


def _fixtures() -> list[pytest.ParameterSet]:
    zc = build_zipcrypto_zip
    return [
        pytest.param(
            lambda: zc(_PASSWORD, b"a.txt", _TEXT, compression=zipfile.ZIP_STORED),
            id="zipcrypto-stored",
        ),
        pytest.param(lambda: zc(_PASSWORD, b"a.txt", _TEXT), id="zipcrypto-deflate"),
        pytest.param(
            lambda: zc(_PASSWORD, b"a.txt", _TEXT, compression=zipfile.ZIP_BZIP2),
            id="zipcrypto-bzip2",
        ),
        pytest.param(
            lambda: zc(_PASSWORD, b"a.txt", _TEXT, compression=zipfile.ZIP_LZMA),
            id="zipcrypto-lzma",
        ),
        pytest.param(lambda: _bit3_stored_zipcrypto(_TEXT), id="zipcrypto-bit3-stored"),
        pytest.param(
            lambda: _bit3_stored_zipcrypto(b""), id="zipcrypto-bit3-stored-empty"
        ),
        pytest.param(
            _shorter_than_its_header, id="zipcrypto-bit3-shorter-than-its-header"
        ),
        pytest.param(
            lambda: _bit3_zipcrypto(zipfile.ZIP_DEFLATED), id="zipcrypto-bit3-deflate"
        ),
        pytest.param(
            lambda: _bit3_zipcrypto(zipfile.ZIP_BZIP2), id="zipcrypto-bit3-bzip2"
        ),
        pytest.param(
            lambda: _bit3_zipcrypto(zipfile.ZIP_LZMA), id="zipcrypto-bit3-lzma"
        ),
        *(
            pytest.param(
                lambda method=method, encode=encode, bit3=bit3: (
                    _zipcrypto_precompressed(method, encode, bit3=bit3)
                ),
                id=f"zipcrypto-{'bit3-' if bit3 else ''}{name}",
                marks=requires(package),
            )
            for name, method, encode, package in (
                ("deflate64", 9, _deflate64, "inflate64"),
                ("ppmd", 98, _ppmd, "pyppmd"),
            )
            for bit3 in (False, True)
        ),
        *(
            pytest.param(
                lambda method=method, encode=encode, version=version: _bit3(
                    _aes_precompressed(method, encode, vendor_version=version)
                ),
                id=f"aes-ae{version}-bit3-{name}",
                marks=[requires("cryptography"), requires(package)],
            )
            for name, method, encode, package in (
                ("deflate64", 9, _deflate64, "inflate64"),
                ("ppmd", 98, _ppmd, "pyppmd"),
            )
            for version in (1, 2)
        ),
        pytest.param(
            lambda: _bit3(_aes_zip(vendor_version=1, method=0)),
            id="aes-ae1-bit3-stored",
            marks=requires("cryptography"),
        ),
        pytest.param(
            lambda: _bit3(_aes_zip(vendor_version=2, method=0)),
            id="aes-ae2-bit3-stored",
            marks=requires("cryptography"),
        ),
        pytest.param(
            lambda: _bit3(_aes_zip(vendor_version=1, method=8)),
            id="aes-ae1-bit3-deflate",
            marks=requires("cryptography"),
        ),
        pytest.param(
            lambda: _bit3(_aes_zip(vendor_version=2, method=8)),
            id="aes-ae2-bit3-deflate",
            marks=requires("cryptography"),
        ),
        pytest.param(
            _aes_shorter_than_its_header,
            id="aes-bit3-shorter-than-its-header",
            marks=requires("cryptography"),
        ),
        pytest.param(
            _aes_shorter_than_its_code,
            id="aes-bit3-shorter-than-its-code",
            marks=requires("cryptography"),
        ),
        pytest.param(
            lambda: _aes_zip(vendor_version=1, method=0),
            id="aes-ae1-stored",
            marks=requires("cryptography"),
        ),
        pytest.param(
            lambda: _aes_zip(vendor_version=1, method=8),
            id="aes-ae1-deflate",
            marks=requires("cryptography"),
        ),
        pytest.param(
            lambda: _aes_zip(vendor_version=2, method=8),
            id="aes-ae2-deflate",
            marks=requires("cryptography"),
        ),
        pytest.param(
            # The overrun's message is the pipe's own copy of the file read's.
            lambda: _declared_size(_aes_zip(method=0), 10),
            id="aes-data-past-its-declared-size",
            marks=requires("cryptography"),
        ),
    ]


def _file_read(data: bytes, password: object) -> dict[str, object]:
    out: dict[str, object] = {}
    with archivey.open_archive(io.BytesIO(data), password=password) as reader:  # type: ignore[arg-type]
        for member in reader.members():
            try:
                out[member.name] = reader.read(member)
            except ArchiveyError as exc:
                out[member.name] = (type(exc), str(exc))
    return out


#: The key under ``_pipe_read``'s result for what ended the walk early.
_WALK_ENDED = "<walk ended>"


def _pipe_read(data: bytes, password: object) -> dict[str, object]:
    out: dict[str, object] = {}
    with archivey.open_archive(
        NonSeekableBytesIO(data),
        streaming=True,
        password=password,  # type: ignore[arg-type]
    ) as reader:
        try:
            for member, stream in reader.stream_members():
                assert stream is not None
                try:
                    out[member.name] = stream.read()
                except ArchiveyError as exc:
                    out[member.name] = (type(exc), str(exc))
        except ArchiveyError as exc:
            out[_WALK_ENDED] = (type(exc), str(exc))
    return out


@pytest.mark.parametrize("build", _fixtures())
def test_a_pipe_decrypts_as_the_file_read_does(build) -> None:
    data = _with_plain_member(build())
    expected = _file_read(data, _PASSWORD)
    assert expected["plain.txt"] == b"plain"
    assert _pipe_read(data, _PASSWORD) == expected
    assert _pipe_read(data, _PASSWORD.decode()) == expected


@pytest.mark.parametrize("build", _fixtures())
def test_a_wrong_or_missing_password_fails_as_from_a_file(build) -> None:
    data = _with_plain_member(build())
    for password in (b"not the password", None):
        expected = _file_read(data, password)
        kind, _ = expected["a.txt"]  # type: ignore[misc]
        # A member too short for its encryption is refused for that under a
        # password, from a file too; with none, the missing password refuses it
        # first, as for the rest.
        if build in _TOO_SHORT and password is not None:
            assert kind is CorruptionError
        else:
            assert issubclass(kind, EncryptionError)
        # A bit-3 codec member's end is found by the scan on its ciphertext when
        # its decode fails, so the pass reads on, as from a file.
        assert _pipe_read(data, password) == expected


def test_real_bit3_members_read_as_from_a_file() -> None:
    """Info-ZIP writes a stored and a deflated member, each with a descriptor."""
    data = _COLLISION.read_bytes()
    expected = _file_read(data, _PASSWORD)
    assert set(expected) == {"stored.txt", "deflated.txt"}
    assert _pipe_read(data, _PASSWORD) == expected


def test_damage_in_an_unread_bit3_codec_member_does_not_end_the_pass() -> None:
    """The scan finds its end on the ciphertext, so damage nobody reads costs
    nothing, as from a file."""
    data = _with_plain_member(
        _bit3(
            corrupt_zipcrypto_payload(
                build_zipcrypto_zip(_PASSWORD, b"a.txt", _TEXT, check_byte=0)
            )
        )
    )
    kind, _message = _file_read(data, _PASSWORD)["a.txt"]  # type: ignore[misc]
    assert kind is EncryptionError
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password=_PASSWORD
    ) as reader:
        read = {
            member.name: stream.read()
            for member, stream in reader.stream_members(lambda m: m.name == "plain.txt")
            if stream is not None
        }
    assert read == {"plain.txt": _file_read(data, _PASSWORD)["plain.txt"]}


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda: _bit3_zipcrypto(zipfile.ZIP_DEFLATED), id="zipcrypto-deflate"
        ),
        pytest.param(
            lambda: _bit3(
                build_zipcrypto_zip(
                    _PASSWORD, b"a.txt", _TEXT, compression=zipfile.ZIP_BZIP2
                )
            ),
            id="zipcrypto-bzip2",
        ),
        pytest.param(
            lambda: _bit3(_aes_zip()), id="aes", marks=requires("cryptography")
        ),
    ],
)
@pytest.mark.parametrize("password", [_PASSWORD, b"not the password", None])
@pytest.mark.parametrize("signed", [True, False], ids=["signed", "unsigned"])
def test_an_unread_bit3_codec_member_is_passed_without_its_key(
    build,
    password: bytes | None,
    signed: bool,
) -> None:
    """The scan finds its end on the ciphertext, by the descriptor and the header
    after it, so neither a missing nor a wrong password stops the pass."""
    data = _with_plain_member(build())
    if not signed:
        data = without_descriptor_signatures(data)
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password=password
    ) as reader:
        read = {
            member.name: stream.read()
            for member, stream in reader.stream_members(lambda m: m.name == "plain.txt")
            if stream is not None
        }
        names = [m.name for m in reader.members_report().members]
    assert names == ["a.txt", "plain.txt"]
    assert read == {"plain.txt": b"plain"}


@pytest.mark.parametrize("compression", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_an_unread_bit3_member_is_passed_with_its_password(compression: int) -> None:
    data = _with_plain_member(_bit3_zipcrypto(compression))
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password=_PASSWORD
    ) as reader:
        names = [member.name for member, _ in reader.stream_members()]
    assert names == ["a.txt", "plain.txt"]


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda: _bit3_zipcrypto(zipfile.ZIP_DEFLATED), id="zipcrypto"),
        pytest.param(
            lambda: _bit3(_aes_zip(method=8)),
            id="aes",
            marks=requires("cryptography"),
        ),
    ],
)
def test_a_bit3_codec_member_cut_inside_its_header_is_truncated(build) -> None:
    data = build()
    name_len, extra_len = struct.unpack_from("<HH", data, 26)
    cut = data[: 30 + name_len + extra_len + 5]
    with archivey.open_archive(
        NonSeekableBytesIO(cut), streaming=True, password=_PASSWORD
    ) as reader:
        passes = reader.stream_members()
        _, stream = next(passes)
        assert stream is not None
        with pytest.raises(TruncatedError):
            stream.read()


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda: _bit3(_aes_zip(vendor_version=1, method=8)),
            id="aes-cut-in-its-code",
            marks=requires("cryptography"),
        ),
        pytest.param(lambda: _bit3_zipcrypto(zipfile.ZIP_DEFLATED), id="zipcrypto"),
    ],
)
def test_a_bit3_codec_member_cut_after_its_codec_ends_the_pass_as_truncated(
    build,
) -> None:
    """The codec ends; the code or the descriptor after it does not come. Going on
    past the member is a truncation too: the scan on the ciphertext finds no
    descriptor before the stream ends."""
    data = build()
    descriptor = data.index(b"PK\x07\x08")
    cut = data[: descriptor - 4]
    result = _pipe_read(cut, _PASSWORD)
    kind, _message = result["a.txt"]  # type: ignore[misc]
    assert kind is TruncatedError
    assert result[_WALK_ENDED][0] is TruncatedError  # type: ignore[index]


@requires("cryptography")
@pytest.mark.parametrize("vendor_version", [1, 2])
def test_a_bit3_aes_member_past_the_kept_window_reads_as_from_a_file(
    vendor_version: int,
) -> None:
    """Over ``_CODEC_RETAIN`` of incompressible data: the code is checked over the
    whole ciphertext, though the walk keeps only the end of it."""
    from tests.zip_aes_fixture import build_aes_zip

    payload = random.Random(0).randbytes(5 << 20)
    data = _bit3(
        build_aes_zip(
            [(b"a.txt", payload)],
            password=_PASSWORD,
            method=8,
            vendor_version=vendor_version,
        )
    )
    expected = _file_read(data, _PASSWORD)
    assert expected == {"a.txt": payload}
    assert _pipe_read(data, _PASSWORD) == expected


def _bit3(data: bytes) -> bytes:
    """``data``'s one member written as a pipe writer would: bit 3, zero CRC and
    sizes in the local header, a signed descriptor after the data."""
    out = bytearray(data)
    flags, crc, csize, usize, name_len, extra_len = struct.unpack_from(
        "<H6xIIIHH", out, 6
    )
    struct.pack_into("<H", out, 6, flags | 0x8)
    struct.pack_into("<III", out, 14, 0, 0, 0)
    end_of_data = 30 + name_len + extra_len + csize
    descriptor = struct.pack("<IIII", 0x08074B50, crc, csize, usize)
    eocd = out.rindex(b"PK\x05\x06")
    (cd_offset,) = struct.unpack_from("<I", out, eocd + 16)
    struct.pack_into("<H", out, cd_offset + 8, flags | 0x8)
    out[end_of_data:end_of_data] = descriptor
    eocd += len(descriptor)
    struct.pack_into("<I", out, eocd + 16, cd_offset + len(descriptor))
    return bytes(out)


def test_a_password_that_only_passes_the_check_byte_fails_as_unverified() -> None:
    """``wrong896`` passes ``stored.txt``'s one-byte check (fixture README); only the
    CRC at the end shows it is wrong, and then it may be a wrong password or damage."""
    data = _COLLISION.read_bytes()
    with (
        archivey.open_archive(io.BytesIO(data), password="wrong896") as reader,
        pytest.raises(EncryptionError) as from_file,
    ):
        reader.read(next(m for m in reader.members() if m.name == "stored.txt"))
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password="wrong896"
    ) as reader:
        passes = reader.stream_members()
        _, stream = next(passes)
        assert stream is not None
        with pytest.raises(EncryptionError) as from_pipe:
            stream.read()
    assert str(from_pipe.value) == str(from_file.value)


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_damage_under_a_zipcrypto_password_fails_as_from_a_file(method: int) -> None:
    data = corrupt_zipcrypto_payload(
        build_zipcrypto_zip(_PASSWORD, b"a.txt", _TEXT, compression=method)
    )
    expected = _file_read(data, _PASSWORD)
    assert expected["a.txt"][0] is EncryptionError  # type: ignore[index]
    assert _pipe_read(data, _PASSWORD) == expected


@requires("cryptography")
@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda data: data, id="sized"),
        pytest.param(_bit3, id="bit3"),
    ],
)
@pytest.mark.parametrize("method", [0, 8])
def test_a_tampered_aes_hmac_fails_as_from_a_file(build, method: int) -> None:
    data = _with_plain_member(
        build(_aes_zip(vendor_version=2, method=method, tamper_hmac=True))
    )
    expected = _file_read(data, _PASSWORD)
    assert expected["a.txt"][0] is CorruptionError  # type: ignore[index]
    assert _pipe_read(data, _PASSWORD) == expected


def _provider(*answers: bytes) -> Callable[[object], bytes | None]:
    """A provider that gives ``answers`` in turn, then ``None``."""
    queue = list(answers)

    def provide(_request: object) -> bytes | None:
        return queue.pop(0) if queue else None

    return provide


_LISTS = [
    pytest.param(lambda: [b"not the password", _PASSWORD], id="wrong-then-right"),
    pytest.param(lambda: [_PASSWORD, b"not the password"], id="right-then-wrong"),
    pytest.param(lambda: [b"not the password", b"nor this"], id="both-wrong"),
    pytest.param(lambda: _provider(b"not the password", _PASSWORD), id="provider"),
]


@pytest.mark.parametrize("passwords", _LISTS)
@pytest.mark.parametrize("build", _fixtures())
def test_several_passwords_read_as_from_a_file(build, passwords) -> None:
    """The confirm runs on the kept first bytes of the data: a candidate it rejects
    is skipped, as from a file."""
    data = _with_plain_member(build())
    expected = _file_read(data, passwords())
    assert _pipe_read(data, passwords()) == expected


def _check_byte_collision(
    data: bytes, start_matches: Callable[[bytes], bool] = lambda _: True
) -> bytes:
    """A wrong password that passes the ZipCrypto check byte of ``data``'s first
    member, as one in 256 does, and whose first two decrypted data bytes pass
    ``start_matches``."""
    from archivey.internal.backends.zipcrypto import keys_after_header

    flags, dos_time, crc = struct.unpack_from("<H2xHxxI", data, 6)
    name_len, extra_len = struct.unpack_from("<HH", data, 26)
    start = 30 + name_len + extra_len
    head = data[start : start + 12]
    expected = (dos_time >> 8) & 0xFF if flags & 0x8 else crc >> 24
    for i in range(200_000):
        wrong = f"collide-{i}".encode()
        keys, check = keys_after_header(wrong, head)
        if check == expected and start_matches(keys.decrypt(data[start + 12 :][:2])):
            return wrong
    raise AssertionError("no check byte collision found")


#: Over the bytes the pass keeps to confirm a password on.
_HUGE = random.Random(6).randbytes(1_200_000)


def _confirmable() -> list[pytest.ParameterSet]:
    zc = build_zipcrypto_zip
    stored = zipfile.ZIP_STORED
    return [
        pytest.param(
            lambda: zc(_PASSWORD, b"a.txt", _TEXT, compression=stored), id="stored"
        ),
        pytest.param(lambda: _bit3_zipcrypto(stored), id="bit3-stored"),
        pytest.param(
            lambda: zc(_PASSWORD, b"a.txt", _LONG, compression=stored), id="stored-long"
        ),
        pytest.param(lambda: zc(_PASSWORD, b"a.txt", _LONG), id="deflate-long"),
        pytest.param(lambda: _bit3_zipcrypto(zipfile.ZIP_DEFLATED), id="bit3-deflate"),
        pytest.param(
            lambda: zc(_PASSWORD, b"a.txt", _LONG, compression=zipfile.ZIP_BZIP2),
            id="bzip2-long",
        ),
    ]


@pytest.mark.parametrize("build", _confirmable())
def test_a_wrong_password_past_the_check_byte_is_rejected_as_from_a_file(
    build,
) -> None:
    """The confirm on the kept bytes rejects it (a CRC within them, or the codec),
    so the right one after it reads the member."""
    data = _with_plain_member(build())
    passwords = [_check_byte_collision(data), _PASSWORD]
    expected = _file_read(data, passwords)
    assert not isinstance(expected["a.txt"], tuple)
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password=passwords
    ) as reader:
        read = {
            member.name: stream.read()
            for member, stream in reader.stream_members()
            if stream is not None
        }
        assert _unverified(reader) == []
    assert read == expected


def _ppmd_restore_2(start: bytes) -> bool:
    """A PPMd header with restore method 2 (freeze) and a valid order and memory."""
    (word,) = struct.unpack("<H", start)
    return word >> 12 == 2 and word & 0xF >= 1


def test_a_wrong_password_with_an_unsupported_codec_header_is_skipped() -> None:
    """A wrong key that passes the check byte can decrypt a PPMd header asking for
    restore method 2. That is the key's garbage, not the archive's, so the right
    password after it reads the member, as from a file."""
    importorskip("pyppmd")
    data = _with_plain_member(
        build_zipcrypto_zip(
            _PASSWORD, b"a.txt", _LONG, compression=98, compressed=_ppmd(_LONG)
        )
    )
    passwords = [_check_byte_collision(data, _ppmd_restore_2), _PASSWORD]
    expected = _file_read(data, passwords)
    assert expected["a.txt"] == _LONG
    assert _pipe_read(data, passwords) == expected


def test_the_confirm_spool_fits_in_the_walks_window() -> None:
    """A short bit-3 codec member's spool runs past its descriptor, which the walk
    finds only among the last ``_CODEC_RETAIN`` bytes it handed out."""
    from archivey.internal.backends import zip_forward_reader, zip_local_walk

    assert zip_forward_reader._CONFIRM_SPOOL <= zip_local_walk._CODEC_RETAIN


@pytest.mark.parametrize("with_right", [True, False], ids=["list", "alone"])
def test_a_wrong_password_running_out_of_an_intact_archive_is_not_a_cut(
    with_right: bool,
) -> None:
    """A bit-3 member's data runs to the stream's end, so a wrong key whose PPMd
    garbage runs out of input there has not met a cut stream: the archive's end
    record went by. The right password after it reads the member; alone, it fails
    as a password that may be wrong, as from a file."""
    importorskip("pyppmd")
    data = _with_plain_member(
        _bit3(
            build_zipcrypto_zip(
                _PASSWORD,
                b"a.txt",
                _TEXT,
                compression=98,
                compressed=_ppmd(_TEXT),
                check_byte=0,
            )
        )
    )
    wrong = _check_byte_collision(data, _ppmd_accepted)
    passwords: object = [wrong, _PASSWORD] if with_right else wrong
    expected = _file_read(data, passwords)
    got = _pipe_read(data, passwords)
    if with_right:
        assert expected["a.txt"] == _TEXT
    else:
        assert expected["a.txt"][0] is EncryptionError  # type: ignore[index]
    assert got == expected


def _ppmd_accepted(start: bytes) -> bool:
    """A decrypted PPMd header archivey accepts (restore 0 or 1, order 2 or more):
    the garbage after it decodes, and here runs out of input."""
    (word,) = struct.unpack("<H", start)
    return word >> 12 <= 1 and word & 0xF >= 1


def test_a_cut_stream_is_damage_with_several_passwords_too() -> None:
    """A stream cut inside a bit-3 member's data is truncation with one password;
    with the right one among several it is the same, not a password failure."""
    data = _bit3_zipcrypto(zipfile.ZIP_DEFLATED)
    cut = data[: len(data) // 2]
    one = _pipe_read(cut, _PASSWORD)["a.txt"]
    assert isinstance(one, tuple)
    assert one[0] is TruncatedError
    assert _pipe_read(cut, [b"not the password", _PASSWORD])["a.txt"] == one


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda: build_zipcrypto_zip(
                _PASSWORD, b"a.txt", _HUGE, compression=zipfile.ZIP_STORED
            ),
            id="stored",
        ),
        pytest.param(
            lambda: _bit3(
                build_zipcrypto_zip(
                    _PASSWORD,
                    b"a.txt",
                    _HUGE,
                    compression=zipfile.ZIP_STORED,
                    check_byte=0,
                )
            ),
            id="bit3-stored",
        ),
    ],
)
def test_several_inconclusive_passwords_take_the_first(build) -> None:
    """Past the kept bytes nothing tells a STORED member's candidates apart, and the
    data goes by once, so the first that passed is read and its CRC at the end is
    the test: a wrong one fails there, as one unconfirmed password does. The file
    read walks each to the end instead (a choice made for pipes, which a spool of
    the whole member could revisit)."""
    data = _with_plain_member(build())
    wrong = _check_byte_collision(data)
    assert _file_read(data, [wrong, _PASSWORD])["a.txt"] == _HUGE
    got = _pipe_read(data, [wrong, _PASSWORD])
    kind, message = got["a.txt"]  # type: ignore[misc]
    assert kind is EncryptionError
    assert "the password may be wrong" in message
    assert got["plain.txt"] == b"plain"
    assert _pipe_read(data, [_PASSWORD, wrong])["a.txt"] == _HUGE


def test_an_inconclusive_password_closed_early_is_reported_as_such() -> None:
    data = _with_plain_member(
        build_zipcrypto_zip(_PASSWORD, b"a.txt", _HUGE, compression=zipfile.ZIP_STORED)
    )
    passwords = [_check_byte_collision(data), _PASSWORD]
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password=passwords[::-1]
    ) as reader:
        for member, stream in reader.stream_members():
            if member.name == "a.txt":
                assert stream is not None
                stream.read(10)
                stream.close()
        assert [c.check for c in _unverified(reader)] == ["confirm_budget_exhausted"]


@requires("cryptography")
@pytest.mark.parametrize("vendor_version", [1, 2])
def test_a_bit3_aes_codec_member_in_the_kept_bytes_is_confirmed(
    vendor_version: int,
) -> None:
    """Its codec ends inside the kept bytes, and the descriptor after it says where
    the code is, so the HMAC confirms the password there, as the file read's walk
    to the end does: closing it early reports nothing."""
    data = _bit3(_aes_zip(vendor_version=vendor_version, method=8))
    passwords = [_PASSWORD, b"not the password"]
    reports = []
    for source in (io.BytesIO(data), NonSeekableBytesIO(data)):
        with archivey.open_archive(
            source, streaming=True, password=passwords
        ) as reader:
            for _member, stream in reader.stream_members():
                assert stream is not None
                assert stream.read(10) == _TEXT[:10]
                stream.close()
            reports.append([c.check for c in _unverified(reader)])
    assert reports == [[], []]


@pytest.mark.parametrize("form", ["value", "list", "provider"])
@pytest.mark.parametrize("read_link_targets", [True, False])
def test_a_long_ciphertext_is_decoded_only_under_read_link_targets(
    read_link_targets: bool, form: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A short-plaintext member whose ciphertext is over what the pass keeps is
    decoded as the pass drains it, which may ask a provider: ``read_link_targets``
    allows that, as for any link target. With it off nothing decrypts the member,
    whatever the password's form. (A kept ciphertext is decrypted once the
    directory makes it a link, which may ask, as from a file.)"""
    data = _with_plain_member(
        build_zipcrypto_zip(
            _PASSWORD,
            b"link",
            b"target.txt",
            unix_mode=0o120777,
            compressed=_padded_deflate(b"target.txt"),
        )
    )
    asked: list[object] = []

    def provider(request: object) -> bytes:
        asked.append(request)
        return _PASSWORD

    password = {
        "value": _PASSWORD,
        "list": [b"not the password", _PASSWORD],
        "provider": provider,
    }[form]
    calls = _counted_decrypts(monkeypatch)
    with archivey.open_archive(
        NonSeekableBytesIO(data),
        streaming=True,
        password=password,  # type: ignore[arg-type]
        config=archivey.ArchiveyConfig(read_link_targets=read_link_targets),
    ) as reader:
        read = {
            member.name: stream.read()
            for member, stream in reader.stream_members(lambda m: m.name == "plain.txt")
            if stream is not None
        }
        report = reader.members_report()
        reasons = [
            getattr(d.context, "reason", None)
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
    assert read == {"plain.txt": b"plain"}
    assert reasons == []
    if read_link_targets:
        assert calls == ["link"]
        assert len(asked) == (form == "provider")
        assert report.members[0].link_target == "target.txt"
    else:
        # Nothing reads a target on its own, so nothing is reported either.
        assert calls == []
        assert asked == []
        assert report.members[0].link_target is None


def _unverified(reader: archivey.ArchiveReader) -> list[EncryptedVerificationContext]:
    return [
        d.context  # type: ignore[misc]
        for d in reader.diagnostics.retained
        if d.code is DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED
    ]


@pytest.mark.parametrize("read_all", [True, False])
def test_a_partial_read_is_reported_as_unverified(read_all: bool) -> None:
    data = _with_plain_member(
        build_zipcrypto_zip(_PASSWORD, b"a.txt", _TEXT, compression=zipfile.ZIP_STORED)
    )
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password=_PASSWORD
    ) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            if member.name == "a.txt":
                with stream:
                    if read_all:
                        assert stream.read() == _TEXT
                    else:
                        # Even all of its bytes: the CRC runs on the read that finds
                        # the end.
                        assert stream.read(len(_TEXT)) == _TEXT
        contexts = _unverified(reader)
    if read_all:
        assert contexts == []
    else:
        (context,) = contexts
        assert context.member_name == "a.txt"
        assert context.check == "weak_open_check"
        assert context.reason == "partial_read"


def _link_targets(data: bytes, password: object, *, pipe: bool) -> list[object]:
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with archivey.open_archive(source, streaming=pipe, password=password) as reader:  # type: ignore[arg-type]
        members = reader.members_report().members
        reasons = [
            getattr(d.context, "reason", None)
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
        return [(m.name, m.type, m.link_target) for m in members] + reasons


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda: build_zipcrypto_zip(
                _PASSWORD, b"link", b"target.txt", unix_mode=0o120777
            ),
            id="zipcrypto",
        ),
        pytest.param(
            lambda: build_zipcrypto_zip(
                _PASSWORD,
                b"link",
                b"target.txt",
                compression=zipfile.ZIP_DEFLATED,
                unix_mode=0o120777,
                compressed=_padded_deflate(b"target.txt"),
            ),
            id="zipcrypto-deflate-padded-past-the-kept-ciphertext",
        ),
        pytest.param(
            lambda: _aes_zip_link(),
            id="aes",
            marks=requires("cryptography"),
        ),
        pytest.param(
            lambda: _declared_size(_aes_zip_link(b"x" * 5000, method=0), 10),
            id="aes-data-past-its-declared-size",
            marks=requires("cryptography"),
        ),
        pytest.param(
            lambda: _declared_size(
                build_zipcrypto_zip(
                    _PASSWORD,
                    b"link",
                    b"x" * 4098,
                    compression=zipfile.ZIP_STORED,
                    unix_mode=0o120777,
                ),
                4096,
            ),
            id="zipcrypto-data-past-its-declared-size",
        ),
        pytest.param(
            lambda: _bit3(_zipcrypto_link(b"target.txt", check_byte=0)),
            id="zipcrypto-bit3-stored",
        ),
        pytest.param(
            # Kept, and too long once decrypted.
            lambda: _bit3(_zipcrypto_link(b"x" * 5000, check_byte=0)),
            id="zipcrypto-bit3-stored-over-the-target-cap",
        ),
        pytest.param(
            # Over the ciphertext the pass keeps: passed without a key.
            lambda: _bit3(_zipcrypto_link(b"x" * 9000, check_byte=0)),
            id="zipcrypto-bit3-stored-over-the-kept-ciphertext",
        ),
        pytest.param(
            lambda: _bit3(_aes_zip_link(method=0)),
            id="aes-bit3-stored",
            marks=requires("cryptography"),
        ),
    ],
)
@pytest.mark.parametrize(
    "password",
    [_PASSWORD, b"not the password", None, [b"not the password", _PASSWORD]],
    ids=["right", "wrong", "none", "list"],
)
def test_an_encrypted_link_target_is_read_as_from_a_file(build, password) -> None:
    """The pass keeps a short member's ciphertext and decrypts it for the target
    once the directory says it is a link, or decrypts it as it drains when the
    stored data is larger than the ciphertext it keeps; either way without the
    caller asking, and the pipe gives what the file gives. Data past a declared
    size under the target cap is damage, not an over-long target."""
    data = build()
    assert _link_targets(data, password, pipe=True) == _link_targets(
        data, password, pipe=False
    )


@pytest.mark.parametrize(
    ("build", "target"),
    [
        pytest.param(
            lambda: _bit3(
                _zipcrypto_link(
                    b"target.txt", check_byte=0, compression=zipfile.ZIP_DEFLATED
                )
            ),
            "target.txt",
            id="zipcrypto",
        ),
        pytest.param(
            lambda: _bit3(_aes_zip_link()),
            "target.txt",
            id="aes",
            marks=requires("cryptography"),
        ),
        pytest.param(
            # Over the ciphertext the pass keeps: passed without a key, and its
            # target too long for one.
            lambda: _bit3(
                _zipcrypto_link(
                    random.Random(1).randbytes(9000),
                    check_byte=0,
                    compression=zipfile.ZIP_DEFLATED,
                )
            ),
            None,
            id="zipcrypto-over-the-kept-ciphertext",
        ),
    ],
)
@pytest.mark.parametrize(
    "password",
    [_PASSWORD, b"not the password", None, [b"not the password", _PASSWORD]],
    ids=["right", "wrong", "none", "list"],
)
def test_a_bit3_codec_link_target_is_read_as_from_a_file(
    build,
    target: str | None,
    password: bytes | None,
) -> None:
    """The pass keeps its ciphertext, found by the scan, and decodes it once the
    directory says it is a link: the pipe gives what the file gives."""
    data = build()
    targets = _link_targets(data, password, pipe=False)
    if password == _PASSWORD:
        assert targets[0] == ("link", archivey.MemberType.SYMLINK, target)
    assert _link_targets(data, password, pipe=True) == targets


def _zipcrypto_link(
    target: bytes,
    *,
    check_byte: int | None = None,
    compression: int = zipfile.ZIP_STORED,
) -> bytes:
    return build_zipcrypto_zip(
        _PASSWORD,
        b"link",
        target,
        compression=compression,
        unix_mode=0o120777,
        check_byte=check_byte,
    )


def _aes_zip_link(target: bytes = b"target.txt", *, method: int = 8) -> bytes:
    from tests.zip_aes_fixture import build_aes_zip

    return build_aes_zip(
        [(b"link", target)], password=_PASSWORD, method=method, unix_mode=0o120777
    )


def _declared_size(data: bytes, size: int) -> bytes:
    """``data``'s one member with ``size`` as its uncompressed size in both headers."""
    out = bytearray(data)
    struct.pack_into("<I", out, 22, size)
    # The directory's offset from the end record: the ciphertext may hold the
    # central header's signature by chance.
    eocd = data.rindex(b"PK\x05\x06")
    (cd_offset,) = struct.unpack_from("<I", data, eocd + 16)
    struct.pack_into("<I", out, cd_offset + 24, size)
    return bytes(out)


def _method_6_link() -> bytes:
    """A ZipCrypto symlink whose method says Implode in both headers: the password
    is right, and the codec is refused once the stage is built."""
    data = bytearray(
        build_zipcrypto_zip(
            _PASSWORD,
            b"link",
            b"target.txt",
            compression=zipfile.ZIP_STORED,
            unix_mode=0o120777,
        )
    )
    struct.pack_into("<H", data, 8, 6)
    struct.pack_into("<H", data, data.index(b"PK\x01\x02") + 10, 6)
    return bytes(data)


def _counted_decrypts(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    from archivey.internal.backends import zip_forward_reader

    calls: list[str] = []
    original = zip_forward_reader._PassData._decrypted

    def counted(self, loc, decode):
        calls.append(self.member.name)
        return original(self, loc, decode)

    monkeypatch.setattr(zip_forward_reader._PassData, "_decrypted", counted)
    return calls


def test_a_link_whose_codec_is_refused_says_so_as_from_a_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Listing keeps the link without a target and says why, from a file and a pipe
    alike; opening the link raises the refusal (DR-2)."""
    data = _method_6_link()
    calls = _counted_decrypts(monkeypatch)
    from_file = _link_target_report(data, pipe=False)
    from_pipe = _link_target_report(data, pipe=True)
    assert from_pipe == from_file
    assert from_file[0] == [("link", archivey.MemberType.SYMLINK, None)]
    assert from_file[1] == ["target_data_unsupported"]
    assert calls == ["link"]
    with (
        archivey.open_archive(io.BytesIO(data), password=_PASSWORD) as reader,
        pytest.raises(UnsupportedFeatureError) as opened,
    ):
        reader.open(reader.get("link"))
    assert from_file[2] == [
        (
            "The symlink target of 'link' could not be read: "
            f"{raw_message_of(opened.value).rstrip('.')}. Leaving link_target unset."
        )
    ]


def _link_target_report(
    data: bytes, *, pipe: bool
) -> tuple[list[object], list[object], list[str]]:
    """The listing, and the reason and message of each ``SYMLINK_TARGET_UNAVAILABLE``."""
    source = NonSeekableBytesIO(data) if pipe else io.BytesIO(data)
    with archivey.open_archive(source, streaming=pipe, password=_PASSWORD) as reader:  # type: ignore[arg-type]
        if pipe:
            for _ in reader.stream_members():
                pass
        members = reader.members_report().members
        diagnostics = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
        return (
            [(m.name, m.type, m.link_target) for m in members],
            [getattr(d.context, "reason", None) for d in diagnostics],
            [d.message for d in diagnostics],
        )


def test_a_failed_open_is_not_retried_on_the_data_past_the_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stage read the encryption header; a second open would read the next
    twelve bytes as one. The caller's error stands, for the link target too."""
    data = _method_6_link()
    calls = _counted_decrypts(monkeypatch)
    with (
        archivey.open_archive(io.BytesIO(data), password=_PASSWORD) as reader,
        pytest.raises(UnsupportedFeatureError) as from_file,
    ):
        reader.read(reader.members()[0])
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password=_PASSWORD
    ) as reader:
        passes = reader.stream_members()
        _, stream = next(passes)
        assert stream is not None
        for _ in range(2):
            with pytest.raises(UnsupportedFeatureError) as from_pipe:
                stream.read()
            assert str(from_pipe.value) == str(from_file.value)
        # The directory makes it a link, and its target is refused as the read
        # was. The pass ends normally and reports the link without a target, as
        # the file's listing does (DR-2); it does not open the data again.
        assert next(passes, None) is None
        (link,) = reader.members_report().members
        assert link.type is archivey.MemberType.SYMLINK
        assert link.link_target is None
        (diagnostic,) = [
            d
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.SYMLINK_TARGET_UNAVAILABLE
        ]
        assert getattr(diagnostic.context, "reason", None) == "target_data_unsupported"
        assert raw_message_of(from_file.value).rstrip(".") in diagnostic.message
    assert calls == ["link"]


@requires("cryptography")
def test_no_key_is_derived_for_a_member_nobody_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Short members are kept as ciphertext in case the directory makes them links;
    only a link's is decrypted, as a file read only reads a link's target."""
    from tests.zip_aes_fixture import build_aes_zip

    data = build_aes_zip(
        [(f"m{i}.txt".encode(), b"x") for i in range(20)], password=_PASSWORD
    )
    calls = _counted_decrypts(monkeypatch)
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password=_PASSWORD
    ) as reader:
        for _ in reader.stream_members():
            pass
        assert len(reader.members_report().members) == 20
    assert calls == []


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda: _bit3_zipcrypto(zipfile.ZIP_STORED), id="zipcrypto-stored"
        ),
        pytest.param(
            lambda: _bit3_zipcrypto(zipfile.ZIP_DEFLATED), id="zipcrypto-deflate"
        ),
        pytest.param(
            lambda: _bit3(_aes_zip(method=0)),
            id="aes-stored",
            marks=requires("cryptography"),
        ),
        pytest.param(
            lambda: _bit3(_aes_zip()),
            id="aes-deflate",
            marks=requires("cryptography"),
        ),
    ],
)
def test_no_key_is_derived_for_a_bit3_member_nobody_reads(
    build,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Its scan finds the end on the ciphertext."""
    data = _with_plain_member(build())
    calls = _counted_decrypts(monkeypatch)
    with archivey.open_archive(
        NonSeekableBytesIO(data), streaming=True, password=_PASSWORD
    ) as reader:
        for _ in reader.stream_members():
            pass
    assert calls == []


def _padded_deflate(data: bytes) -> bytes:
    """``data`` as raw deflate after 1700 empty stored blocks: a valid member whose
    stored length (8.5 KB) is out of all proportion to its 10 bytes."""
    body = zlib.compressobj(9, zlib.DEFLATED, -15)
    return b"\x00\x00\x00\xff\xff" * 1700 + body.compress(data) + body.flush()
