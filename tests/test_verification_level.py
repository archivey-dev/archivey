"""``ArchiveStream.verified`` and ``verifiable``: what a member stream has checked.

The level must never claim a check that did not run: the weak-password cases are the
ones that matter most, since a wrong key there decrypts to readable bytes with no
error until the checksum at the end (``verification-level`` change).
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from archivey import Verification, open_archive, open_stream
from archivey.exceptions import CorruptionError, EncryptionError
from archivey.types import ArchiveMember
from tests.conftest import requires, requires_binary, run_7z

_FIXTURES = Path(__file__).parent / "fixtures"
_COLLISION = _FIXTURES / "zipcrypto" / "check_byte_collision.zip"
# A wrong password that passes `stored.txt`'s check byte (tests/fixtures/zipcrypto/README.md).
_STORED_COLLISION = "wrong896"
_AE1 = _FIXTURES / "external" / "aes_ae1_pyzipper036.zip"
_RAR4 = _FIXTURES / "rar" / "encryption__rar4.rar"
_RAR4_LEAKING_WRONG = "wrong3"  # secret.txt: 14 bytes out, exit 3
_RAR4_LARGE_STORED = _FIXTURES / "rar" / "encryption_large_stored__rar4.rar"
_RAR5 = _FIXTURES / "rar" / "encryption__.rar"

_DATA = b"verification level\n" * 4000

NONE = Verification.NONE
KEY = Verification.KEY
STRUCTURE = Verification.STRUCTURE
CONTENT = Verification.CONTENT


def _zip(tmp_path: Path, data: bytes = _DATA) -> Path:
    path = tmp_path / "a.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", data)
    return path


def _corrupt_zip_crc(path: Path) -> None:
    """Flip the stored CRC-32 in the local header and the central directory."""
    raw = bytearray(path.read_bytes())
    local = raw.index(b"PK\x03\x04")
    central = raw.index(b"PK\x01\x02")
    for at in (local + 14, central + 16):
        (crc,) = struct.unpack_from("<I", raw, at)
        struct.pack_into("<I", raw, at, crc ^ 0xFFFFFFFF)
    path.write_bytes(bytes(raw))


def _member(reader: object, name: str) -> ArchiveMember:
    return next(m for m in reader.members() if m.name == name)  # type: ignore[attr-defined]


def _first_file(reader: object) -> ArchiveMember:
    return next(m for m in reader.members() if m.is_file)  # type: ignore[attr-defined]


# --- unencrypted ---------------------------------------------------------------------


def test_zip_member_levels_through_a_read(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path)) as reader, reader.open("a.txt") as stream:
        assert (stream.verified, stream.verifiable) == (KEY, CONTENT)
        stream.read(10)
        assert stream.verified is KEY
        assert stream.read() == _DATA[10:]
        assert stream.verified is CONTENT


def test_zip_member_level_stays_after_a_rewind(tmp_path: Path) -> None:
    with (
        open_archive(_zip(tmp_path), seekable_members=True) as reader,
        reader.open("a.txt") as stream,
    ):
        stream.read()
        stream.seek(0)
        stream.read(10)
        assert stream.verified is CONTENT


def test_zip_member_whose_crc_fails_stays_below_structure(tmp_path: Path) -> None:
    path = _zip(tmp_path)
    _corrupt_zip_crc(path)
    with open_archive(path) as reader, reader.open("a.txt") as stream:
        with pytest.raises(CorruptionError):
            stream.read()
        assert stream.verified is KEY
        assert stream.verifiable is CONTENT


def test_stream_members_stream_is_none_until_its_first_read(tmp_path: Path) -> None:
    with open_archive(_zip(tmp_path), streaming=True) as reader:
        for _member_, stream in reader.stream_members():
            assert stream.verified is NONE
            # Asking opens nothing.
            assert stream._inner is None
            stream.read()
            assert (stream.verified, stream.verifiable) == (CONTENT, CONTENT)


def test_tar_member_reaches_structure(tmp_path: Path) -> None:
    path = tmp_path / "a.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo("a.txt")
        info.size = len(_DATA)
        tf.addfile(info, io.BytesIO(_DATA))
    with open_archive(path) as reader, reader.open("a.txt") as stream:
        assert stream.verifiable is STRUCTURE
        stream.read(10)
        assert stream.verified is KEY
        stream.read()
        # The archive's gzip CRC covers the whole archive, not this member.
        assert (stream.verified, stream.verifiable) == (STRUCTURE, STRUCTURE)


@pytest.mark.parametrize(
    ("compress", "expected"),
    [
        pytest.param(gzip.compress, CONTENT, id="gzip"),
        pytest.param(bz2.compress, CONTENT, id="bzip2"),
        # Whether an xz stream carries a check is per stream; not traced yet.
        pytest.param(lzma.compress, STRUCTURE, id="xz"),
    ],
)
def test_open_stream_reaches_what_its_codec_checks(compress, expected) -> None:
    with open_stream(io.BytesIO(compress(_DATA))) as stream:
        assert stream.verifiable is expected
        assert stream.verified is KEY
        assert stream.read() == _DATA
        assert stream.verified is expected


def test_gzip_whose_crc_fails_does_not_reach_content() -> None:
    raw = bytearray(gzip.compress(_DATA))
    raw[-8] ^= 0xFF  # the CRC-32 in the trailer
    with open_stream(io.BytesIO(bytes(raw))) as stream:
        with pytest.raises(CorruptionError):
            stream.read()
        assert stream.verified is KEY


def test_gzip_member_seek_skips_the_codec_check_until_a_rewind(tmp_path: Path) -> None:
    path = tmp_path / "a.txt.gz"
    path.write_bytes(gzip.compress(_DATA))
    with (
        open_archive(path, seekable_members=True) as reader,
        reader.open(_first_file(reader)) as stream,
    ):
        stream.seek(1000)
        stream.read()
        assert stream.verified < CONTENT
        stream.seek(0)
        assert stream.read() == _DATA
        assert stream.verified is CONTENT


# --- passwords -----------------------------------------------------------------------


def test_zipcrypto_partial_read_is_none_under_the_right_password() -> None:
    # One password, a one-byte check: nothing tells the right key from a colliding one.
    with (
        open_archive(_COLLISION, password="secret") as reader,
        reader.open(_member(reader, "stored.txt")) as stream,
    ):
        assert (stream.verified, stream.verifiable) == (NONE, CONTENT)
        stream.read(5)
        assert stream.verified is NONE
        stream.read()
        assert stream.verified is CONTENT


def test_zipcrypto_colliding_wrong_password_never_rises() -> None:
    with (
        open_archive(_COLLISION, password=_STORED_COLLISION) as reader,
        reader.open(_member(reader, "stored.txt")) as stream,
    ):
        stream.read(16)
        assert stream.verified is NONE
        with pytest.raises(EncryptionError):
            stream.read()
        assert stream.verified is NONE


def test_zipcrypto_candidate_confirmed_on_its_crc_is_key() -> None:
    with (
        open_archive(_COLLISION, password=[_STORED_COLLISION, "secret"]) as reader,
        reader.open(_member(reader, "stored.txt")) as stream,
    ):
        stream.read(5)
        assert stream.verified is KEY


@requires("cryptography")
@pytest.mark.parametrize("seekable", [False, True])
def test_winzip_aes_reaches_content_only_through_its_hmac(seekable: bool) -> None:
    with (
        open_archive(_AE1, password="secret", seekable_members=seekable) as reader,
        reader.open(_first_file(reader)) as stream,
    ):
        assert stream.verifiable is CONTENT
        if seekable:
            stream.seek(1)
        stream.read(1)
        # The two-byte password check can pass by chance.
        assert stream.verified is NONE
        stream.read()
        assert stream.verified is CONTENT


@requires_binary("unrar")
def test_rar4_partial_read_is_none_and_full_read_content() -> None:
    with (
        open_archive(_RAR4_LARGE_STORED, password="password") as reader,
        reader.open(_first_file(reader)) as stream,
    ):
        stream.read(100)
        assert (stream.verified, stream.verifiable) == (NONE, CONTENT)
        stream.read()
        assert stream.verified is CONTENT


@requires_binary("unrar")
def test_rar4_stream_members_partial_read_is_none() -> None:
    with open_archive(
        _RAR4_LARGE_STORED, password="password", streaming=True
    ) as reader:
        for member, stream in reader.stream_members():
            if not member.is_file:
                continue
            stream.read(100)
            assert stream.verified is NONE
            stream.read()
            assert stream.verified is CONTENT


@requires_binary("unrar")
def test_rar4_wrong_password_never_rises() -> None:
    with (
        open_archive(_RAR4, password=_RAR4_LEAKING_WRONG) as reader,
        reader.open(_member(reader, "secret.txt")) as stream,
    ):
        stream.read(4)
        assert stream.verified is NONE
        with pytest.raises((EncryptionError, CorruptionError)):
            stream.read()
        assert stream.verified is NONE


@requires("cryptography")
@requires_binary("unrar")
def test_rar5_password_check_is_key_before_the_crc() -> None:
    with (
        open_archive(_RAR5, password="password") as reader,
        reader.open(_first_file(reader)) as stream,
    ):
        assert stream.verified is KEY
        stream.read()
        assert stream.verified is CONTENT


@requires("cryptography")
@requires_binary("7z")
def test_sevenzip_unconfirmed_folder_partial_read_is_none(tmp_path: Path) -> None:
    source = tmp_path / "a.txt"
    source.write_bytes(_DATA)
    archive = tmp_path / "a.7z"
    run_7z(["a", "-t7z", "-pPW", str(archive), str(source)], check=True)
    with (
        open_archive(archive, password="PW") as reader,
        reader.open(_first_file(reader)) as stream,
    ):
        stream.read(100)
        assert (stream.verified, stream.verifiable) == (NONE, CONTENT)
        stream.read()
        assert stream.verified is CONTENT


@requires("cryptography")
def test_winzip_aes_stream_members_partial_read_is_none() -> None:
    with open_archive(_AE1, password="secret", streaming=True) as reader:
        for member, stream in reader.stream_members():
            if not member.is_file:
                continue
            stream.read(1)
            assert stream.verified is NONE
            stream.read()
            assert stream.verified is CONTENT


@requires("cryptography")
def test_winzip_aes_ae2_reaches_content_from_its_hmac(tmp_path: Path) -> None:
    from tests.zip_aes_fixture import build_aes_zip

    # AE-2 stores CRC 0: the HMAC is the only check over the member's bytes.
    path = tmp_path / "ae2.zip"
    path.write_bytes(
        build_aes_zip([(b"a.txt", _DATA)], password=b"secret", vendor_version=2)
    )
    with (
        open_archive(path, password="secret") as reader,
        reader.open("a.txt") as stream,
    ):
        assert stream.verifiable is CONTENT
        stream.read(1)
        assert stream.verified is NONE
        assert stream.read() == _DATA[1:]
        assert stream.verified is CONTENT


@requires("cryptography")
@requires_binary("7z")
def test_sevenzip_unconfirmed_folder_stream_members_partial_read_is_none(
    tmp_path: Path,
) -> None:
    source = tmp_path / "a.txt"
    source.write_bytes(_DATA)
    archive = tmp_path / "a.7z"
    run_7z(["a", "-t7z", "-pPW", str(archive), str(source)], check=True)
    with open_archive(archive, password="PW", streaming=True) as reader:
        for member, stream in reader.stream_members():
            if not member.is_file:
                continue
            stream.read(100)
            assert stream.verified is NONE
            stream.read()
            assert stream.verified is CONTENT


@pytest.mark.parametrize("confirmed", [False, True])
def test_weak_key_with_no_digest_can_reach_nothing(confirmed: bool) -> None:
    # The stack under a member with no stored digest whose password only a weak check
    # accepted (a 7z AES member with no CRC): the password watch alone.
    from archivey.internal.password_confirm import UnverifiedPasswordReadWatch
    from archivey.internal.streams.archive_stream import ArchiveStream

    doubt = [True]

    def watch() -> UnverifiedPasswordReadWatch:
        return UnverifiedPasswordReadWatch(
            io.BytesIO(_DATA),
            size=len(_DATA),
            on_unverified=lambda _message: None,
            key_in_doubt=lambda: doubt[0],
        )

    with ArchiveStream._blank()._setup(watch, translate=lambda _exc: None) as stream:
        assert (stream.verified, stream.verifiable) == (NONE, NONE)
        assert stream.read() == _DATA
        # Read to the end, and still nothing proves the key.
        assert (stream.verified, stream.verifiable) == (NONE, NONE)
        if confirmed:
            doubt[0] = False  # another member's checksum confirmed the password
            assert (stream.verified, stream.verifiable) == (STRUCTURE, STRUCTURE)


@pytest.mark.parametrize("measured", [False, True])
def test_gzip_member_reaches_content_with_measurement(
    tmp_path: Path, measured: bool
) -> None:
    from contextlib import nullcontext

    from archivey.internal.measurement import enable_measurement

    path = tmp_path / "one.gz"
    path.write_bytes(gzip.compress(_DATA))
    with (
        enable_measurement() if measured else nullcontext(),
        open_archive(path) as reader,
        reader.open(_first_file(reader)) as stream,
    ):
        assert stream.read() == _DATA
        assert (stream.verified, stream.verifiable) == (CONTENT, CONTENT)
