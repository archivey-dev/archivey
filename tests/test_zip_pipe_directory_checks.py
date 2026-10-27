"""A ZIP from a pipe checks each member against the central directory, and fails it
with the error a file read gives where the pass can tell.

The pass reads each member's data as its local header describes it, and meets the
directory only at the end. A member whose local header the directory contradicts in a
field a read relies on fails there, after its data was yielded: a file read, which
reads by the directory, would have read it differently.
"""

from __future__ import annotations

import io
import struct
import sys
import zipfile
import zlib

import pytest

import archivey
from archivey.exceptions import CorruptionError, EncryptionError, TruncatedError
from archivey.internal import password_confirm
from archivey.internal.backends import zip_reader
from tests.conftest import requires
from tests.streams_util import NonSeekableBytesIO
from tests.zip_aes_fixture import build_aes_zip
from tests.zipcrypto import build_zipcrypto_zip


def _zip(
    payload: bytes = b"hello world", method: int = zipfile.ZIP_STORED
) -> bytearray:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        z.writestr("a.txt", payload)
    return bytearray(buf.getvalue())


def _drain(data: bytes, **kwargs: object) -> list[bytes]:
    """Every member's bytes from a pass over ``data`` read from a pipe."""
    read = []
    with archivey.open_archive(
        NonSeekableBytesIO(data),
        streaming=True,
        **kwargs,  # type: ignore[arg-type]
    ) as archive:
        for _, stream in archive.stream_members():
            if stream is not None:
                read.append(stream.read())
    return read


def _central(raw: bytearray) -> int:
    return raw.index(b"PK\x01\x02")


@pytest.mark.parametrize(
    ("field", "at", "fmt", "value"),
    [
        ("CRC", 16, "<I", 0x1234_5678),
        ("compressed size", 20, "<I", 5),
        ("size", 24, "<I", 5),
    ],
)
def test_a_directory_entry_contradicting_the_local_header_fails_the_member(
    field: str, at: int, fmt: str, value: int
) -> None:
    """The pass read the data the local header describes and checked it against that
    header; the directory describes other data, so the member fails at the end."""
    raw = _zip()
    struct.pack_into(fmt, raw, _central(raw) + at, value)
    with (
        archivey.open_archive(io.BytesIO(bytes(raw))) as archive,
        pytest.raises(CorruptionError),
    ):
        archive.read("a.txt")
    with pytest.raises(
        CorruptionError, match="local header and its central directory entry disagree"
    ):
        _drain(bytes(raw))


def test_an_encryption_flag_only_the_directory_sets_fails_the_member() -> None:
    raw = _zip()
    central = _central(raw)
    flags = struct.unpack_from("<H", raw, central + 8)[0]
    struct.pack_into("<H", raw, central + 8, flags | 0x1)
    message = r"\(encrypted in the directory, not in the local header\)"
    with pytest.raises(CorruptionError, match=message):
        _drain(bytes(raw))


@requires("inflate64")
def test_a_method_the_two_headers_disagree_on_does_not_fail_a_member_its_crc_checks() -> (
    None
):
    """The data matched the CRC and size the directory gives. A file read decodes by
    the local method too, and both report ``MEMBER_LOCAL_METHOD_DIFFERS``."""
    raw = _zip(b"hello world" * 20, zipfile.ZIP_DEFLATED)
    struct.pack_into("<H", raw, 8, 9)  # Deflate64 decodes this Deflate stream too
    code = archivey.DiagnosticCode.MEMBER_LOCAL_METHOD_DIFFERS
    with archivey.open_archive(NonSeekableBytesIO(bytes(raw)), streaming=True) as pipe:
        read = [stream.read() for _, stream in pipe.stream_members() if stream]
        assert read == [b"hello world" * 20]
        assert pipe.diagnostics.counts[code] == 1
    with archivey.open_archive(io.BytesIO(bytes(raw))) as archive:
        assert archive.read("a.txt") == b"hello world" * 20
        assert archive.diagnostics.counts[code] == 1


@requires("cryptography")
def test_a_crc_the_two_headers_disagree_on_does_not_fail_an_ae2_member() -> None:
    """WinZip AE-2 stores no CRC to check (the authentication code stands in for it),
    so neither read compares one."""
    raw = bytearray(build_aes_zip([(b"a.bin", b"payload")], password=b"right"))
    struct.pack_into("<I", raw, _central(raw) + 16, 0x1234_5678)
    with archivey.open_archive(io.BytesIO(bytes(raw)), password=b"right") as archive:
        assert archive.read("a.bin") == b"payload"
    assert _drain(bytes(raw), password=b"right") == [b"payload"]


def test_a_member_decoding_short_of_its_size_is_truncation_as_from_a_file() -> None:
    raw = _zip(b"hello world" * 20, zipfile.ZIP_DEFLATED)
    for at in (22, _central(raw) + 24):  # the size, in both headers
        struct.pack_into("<I", raw, at, 1000)
    message = r"Decompressed content ended after 220 of 1000 expected bytes\."
    with (
        archivey.open_archive(io.BytesIO(bytes(raw))) as archive,
        pytest.raises(TruncatedError, match=message),
    ):
        archive.read("a.txt")
    with pytest.raises(TruncatedError, match=message):
        _drain(bytes(raw))


def test_a_local_name_the_utf8_flag_mislabels_reads_by_the_directory_name() -> None:
    """The name is compared with the directory's as bytes, as from a file, instead of
    ending the pass before the member, and the directory's name is the member's."""
    raw = _zip()
    flags = struct.unpack_from("<H", raw, 6)[0]
    struct.pack_into("<H", raw, 6, flags | 0x800)
    raw[30] = 0xFF  # the local name's first byte; the central name is untouched
    with archivey.open_archive(io.BytesIO(bytes(raw))) as archive:
        assert archive.read("a.txt") == b"hello world"
    read: list[bytes] = []
    with archivey.open_archive(
        NonSeekableBytesIO(bytes(raw)), streaming=True
    ) as archive:
        for _, stream in archive.stream_members():
            assert stream is not None
            read.append(stream.read())
        report = archive.members_report()
    assert read == [b"hello world"]
    assert report.error is None
    assert [m.name for m in report.members] == ["a.txt"]


def test_damage_past_the_prefix_under_a_lone_surviving_password_is_the_codecs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Of several passwords, one passed the check byte and its prefix decoded: the
    data can only be under that key, so a failure further in is the codec's, as from
    a file, not the "password may be wrong" ambiguity."""
    right = b"very_secret_password"
    plaintext = b"prefix-ok-then-corrupt\n" * 8000
    blob = bytearray(build_zipcrypto_zip(right, b"a.txt", plaintext))
    name_len, extra_len = struct.unpack_from("<HH", blob, 26)
    compressed_size = struct.unpack_from("<I", blob, 18)[0]
    blob[30 + name_len + extra_len + compressed_size - 8] ^= 0xFF
    monkeypatch.setattr(password_confirm, "PASSWORD_CONFIRM_PREFIX_BYTES", 4096)
    monkeypatch.setattr(zip_reader, "PASSWORD_CONFIRM_PREFIX_BYTES", 4096)
    passwords = [right, b"also-wrong"]
    with (
        archivey.open_archive(io.BytesIO(bytes(blob)), password=passwords) as archive,
        pytest.raises(TruncatedError),
    ):
        archive.read("a.txt")
    with pytest.raises(TruncatedError) as caught:
        _drain(bytes(blob), password=passwords)
    assert not isinstance(caught.value, EncryptionError)


@requires("cryptography")
def test_an_aes_member_short_of_its_size_under_several_passwords_is_truncation() -> (
    None
):
    raw = bytearray(
        build_aes_zip([(b"a.bin", b"hello world" * 40)], password=b"right", method=0)
    )
    for signature, at in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        struct.pack_into("<I", raw, raw.index(signature) + at, 100_000)
    passwords = [b"right", b"wrong"]
    with (
        archivey.open_archive(io.BytesIO(bytes(raw)), password=passwords) as archive,
        pytest.raises(TruncatedError),
    ):
        archive.read("a.bin")
    with pytest.raises(TruncatedError):
        _drain(bytes(raw), password=passwords)


def _remethoded_and_missing(n: int, *, central_method: int) -> bytes:
    """``n`` stored members whose directory entries name ``central_method``, then ``n``
    directory entries pointing one byte into a member, where no local header starts."""
    body = bytearray()
    directory = bytearray()
    starts = []
    crc = zlib.crc32(b"x")
    for i in range(n):
        name = f"m{i}".encode()
        starts.append(len(body))
        body += struct.pack(
            "<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0x21, crc, 1, 1, len(name), 0
        )
        body += name + b"x"
    for prefix, method, shift in ((b"m", central_method, 0), (b"g", 0, 1)):
        for i in range(n):
            name = prefix + str(i).encode()
            directory += struct.pack(
                "<4sHHHHHHIIIHHHHHII",
                b"PK\x01\x02",
                20,
                20,
                0,
                method,
                0,
                0x21,
                crc,
                1,
                1,
                len(name),
                0,
                0,
                0,
                0,
                0,
                starts[i] + shift,
            )
            directory += name
    end = struct.pack(
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, 2 * n, 2 * n, len(directory), len(body), 0
    )
    return bytes(body + directory + end)


def _pass_calls(data: bytes) -> int:
    """How many Python calls a pass over ``data`` makes, generator resumptions
    included: a count, so the test does not depend on the machine's speed."""
    calls = 0

    def count(_frame: object, event: str, _arg: object) -> None:
        nonlocal calls
        if event == "call":
            calls += 1

    with archivey.open_archive(NonSeekableBytesIO(data), streaming=True) as archive:
        sys.setprofile(count)
        try:
            with pytest.raises(CorruptionError, match="no local header"):
                for _ in archive.stream_members():
                    pass
        finally:
            sys.setprofile(None)
    return calls


def test_many_method_differences_beside_many_failures_stay_linear() -> None:
    """Members whose directory names another method, beside as many entries with no
    local header: doubling both about doubles the pass's calls. A scan of the
    failures per reported member made it grow fourfold (quadratic)."""
    small = _pass_calls(_remethoded_and_missing(400, central_method=8))
    large = _pass_calls(_remethoded_and_missing(800, central_method=8))
    assert large < 2.5 * small
