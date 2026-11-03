"""Levels a streaming ZIP pass proves (``verification-level-redesign``, task 3.3b).

A forward pass over a ZIP checks each member it decodes against the CRC in its local
header or data descriptor, whether the caller reads the member or the pass decodes it
on its own. That check raises the member, and the central directory read at the end
of the pass does not undo it: a level never falls.
"""

from __future__ import annotations

import io
import struct
import zipfile

import pytest

from archivey import Verification, open_archive
from archivey.types import ArchiveMember
from tests.conftest import requires
from tests.streams_util import NonSeekableBytesIO
from tests.zip_aes_fixture import build_aes_zip
from tests.zipcrypto import build_zipcrypto_zip, find_check_byte_collision

_CHECKED = (Verification.CHECKSUM, Verification.CHECKSUM)
_FILES = {"a": b"first " * 1000, "b": b"second"}


class _Unseekable(io.RawIOBase):
    """A writer that cannot seek, so ``zipfile`` writes a data descriptor."""

    def __init__(self) -> None:
        self.data = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:  # type: ignore[override]
        self.data += b
        return len(b)


def _zip(method: int, *, descriptors: bool) -> bytes:
    out: io.RawIOBase | io.BytesIO = _Unseekable() if descriptors else io.BytesIO()
    with zipfile.ZipFile(out, "w", method) as zf:
        for name, data in _FILES.items():
            zf.writestr(name, data)
    if isinstance(out, _Unseekable):
        return bytes(out.data)
    assert isinstance(out, io.BytesIO)
    return out.getvalue()


def _levels(members: list[ArchiveMember]) -> dict[str, tuple[Verification, ...]]:
    return {m.name: (m.verified, m.verifiable) for m in members}


@pytest.mark.parametrize("descriptors", [True, False], ids=["descriptor", "sized"])
@pytest.mark.parametrize(
    "method", [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED], ids=["deflate", "stored"]
)
def test_a_pass_read_reaches_checksum_and_keeps_it(
    method: int, descriptors: bool
) -> None:
    data = _zip(method, descriptors=descriptors)
    with open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        seen = []
        for member, stream in reader.stream_members():
            assert stream is not None
            assert stream.read() == _FILES[member.name]
            assert (stream.verified, stream.verifiable) == _CHECKED
            seen.append(member)
    # The central directory, read after the last member, does not lower them.
    assert _levels(seen) == dict.fromkeys(_FILES, _CHECKED)


def test_a_member_the_pass_decodes_on_its_own_is_raised() -> None:
    # The pass decodes a short member it passes, to keep it in case the directory
    # makes it a link, and checks it against its descriptor's CRC.
    data = _zip(zipfile.ZIP_DEFLATED, descriptors=True)
    with open_archive(NonSeekableBytesIO(data), streaming=True) as reader:
        report = reader.members_report()
    assert report.error is None
    levels = _levels(list(report.members))
    assert levels["b"] == _CHECKED
    for verified, verifiable in levels.values():
        assert verified <= verifiable


def test_a_descriptor_crc_that_does_not_match_raises_nothing() -> None:
    raw = bytearray(_zip(zipfile.ZIP_DEFLATED, descriptors=True))
    # b's data descriptor: signature, then its CRC-32.
    at = raw.rindex(b"PK\x07\x08") + 4
    (crc,) = struct.unpack_from("<I", raw, at)
    struct.pack_into("<I", raw, at, crc ^ 0xFFFFFFFF)
    with open_archive(NonSeekableBytesIO(bytes(raw)), streaming=True) as reader:
        report = reader.members_report()
    levels = _levels(list(report.members))
    assert levels["b"][0] < Verification.LENGTH


# --- Encrypted members (review round 1, K1 and K2) ----------------------------------

_SECRET = b"secret data\n" * 200


def _bit3(blob: bytes) -> bytes:
    """``blob``'s one member moved to bit 3: the flag set in both headers, the local
    header's CRC and sizes zeroed, and a signed data descriptor after its data."""
    raw = bytearray(blob)
    local = raw.index(b"PK\x03\x04")
    crc, compressed, size = struct.unpack_from("<III", raw, local + 14)
    struct.pack_into("<III", raw, local + 14, 0, 0, 0)
    raw[local + 6] |= 0x08
    cd = raw.index(b"PK\x01\x02")
    raw[cd + 8] |= 0x08
    descriptor = b"PK\x07\x08" + struct.pack("<III", crc, compressed, size)
    raw[cd:cd] = descriptor
    end = raw.rindex(b"PK\x05\x06")
    (offset,) = struct.unpack_from("<I", raw, end + 16)
    struct.pack_into("<I", raw, end + 16, offset + len(descriptor))
    return bytes(raw)


def _pass_read(data: bytes, password: bytes) -> tuple[ArchiveMember, Exception | None]:
    """Read the one member through a pass over a pipe; the member and what raised."""
    with open_archive(
        NonSeekableBytesIO(data), streaming=True, password=password
    ) as reader:
        for member, stream in reader.stream_members():
            assert stream is not None
            try:
                assert stream.read() == _SECRET
            except Exception as exc:  # noqa: BLE001 — the test checks what raised
                return member, exc
            assert (stream.verified, stream.verifiable) == (
                member.verified,
                member.verifiable,
            )
            return member, None
    raise AssertionError("no member")


def test_a_zipcrypto_member_whose_crc_matches_reaches_checksum() -> None:
    # Fails if the pass raises nothing (the member stays at NONE: the check byte alone
    # proves no key).
    member, error = _pass_read(build_zipcrypto_zip(b"pw", b"a", _SECRET), b"pw")
    assert error is None
    assert (member.verified, member.verifiable) == _CHECKED


def test_a_zipcrypto_password_that_passes_only_the_check_byte_raises_nothing() -> None:
    # Fails if the raise ran before the CRC comparison.
    blob = build_zipcrypto_zip(b"pw", b"a", _SECRET)
    wrong = find_check_byte_collision(blob, "a", b"pw")
    member, error = _pass_read(blob, wrong)
    assert error is not None
    assert member.verified is Verification.NONE


@requires("cryptography")
@pytest.mark.parametrize("vendor_version", [1, 2], ids=["AE-1", "AE-2"])
@pytest.mark.parametrize("bit3", [False, True], ids=["sized", "descriptor"])
def test_a_winzip_aes_member_whose_code_matches_reaches_checksum(
    vendor_version: int, bit3: bool
) -> None:
    # AE-2 stores no CRC: only the stage's HMAC answer raises it. Fails, for a sized
    # AE-2 member, if _finish asks only the bit-3 _aes_pass (review round 1, K1).
    blob = build_aes_zip(
        [(b"a", _SECRET)], password=b"pw", vendor_version=vendor_version
    )
    member, error = _pass_read(_bit3(blob) if bit3 else blob, b"pw")
    assert error is None
    assert (member.verified, member.verifiable) == _CHECKED


@requires("cryptography")
@pytest.mark.parametrize("bit3", [False, True], ids=["sized", "descriptor"])
def test_a_winzip_aes_code_that_does_not_match_raises_nothing(bit3: bool) -> None:
    blob = build_aes_zip(
        [(b"a", _SECRET)], password=b"pw", vendor_version=2, tamper_hmac=True
    )
    member, error = _pass_read(_bit3(blob) if bit3 else blob, b"pw")
    assert error is not None
    assert member.verified < Verification.LENGTH
