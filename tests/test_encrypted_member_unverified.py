"""``ENCRYPTED_MEMBER_UNVERIFIED``: a partial read under a password no digest checked.

A ZipCrypto password that passes the one-byte header check can be wrong, and then the
member decrypts to readable garbage that only the CRC at EOF notices. A caller who stops
reading before EOF never hears about it, unless this diagnostic fires. It must fire for
exactly that shape and stay silent when the password was checked against a digest.
"""

from __future__ import annotations

import contextlib
import subprocess
from pathlib import Path

import pytest

from archivey import ArchiveyConfig, DiagnosticPolicy, open_archive
from archivey.diagnostics import (
    ARCHIVE_INTEGRITY_CODES,
    DiagnosticCode,
    EncryptedVerificationContext,
)
from archivey.exceptions import CorruptionError, DiagnosticRaisedError, EncryptionError
from archivey.types import ArchiveMember
from tests.conftest import requires, requires_binary

_FIXTURES = Path(__file__).parent / "fixtures"
_COLLISION = _FIXTURES / "zipcrypto" / "check_byte_collision.zip"
_AE1 = _FIXTURES / "external" / "aes_ae1_pyzipper036.zip"
# Wrong passwords that pass `stored.txt`'s check byte (tests/fixtures/zipcrypto/README.md).
_STORED_COLLISION = "wrong896"
_CODE = DiagnosticCode.ENCRYPTED_MEMBER_UNVERIFIED


def _plaintext(name: str) -> bytes:
    with open_archive(_COLLISION, password="secret") as reader:
        return reader.read(_member(reader, name))


def _member(reader: object, name: str) -> ArchiveMember:
    return next(m for m in reader.members() if m.name == name)  # type: ignore[attr-defined]


def _unverified(reader: object) -> list[EncryptedVerificationContext]:
    diagnostics = reader.diagnostics.retained  # type: ignore[attr-defined]
    contexts = [d.context for d in diagnostics if d.code is _CODE]
    assert all(isinstance(c, EncryptedVerificationContext) for c in contexts)
    return contexts


def _unverified_message(reader: object) -> str:
    diagnostics = reader.diagnostics.retained  # type: ignore[attr-defined]
    (message,) = [d.message for d in diagnostics if d.code is _CODE]
    return message


def test_colliding_zipcrypto_password_partial_read_is_reported() -> None:
    with open_archive(_COLLISION, password=_STORED_COLLISION) as reader:
        member = _member(reader, "stored.txt")
        with reader.open(member) as stream:
            # The colliding password reaches the read (it is not refused at the check
            # byte) and returns bytes that are not the member's.
            head = stream.read(16)
        assert len(head) == 16 and head != _plaintext("stored.txt")[:16]
        (context,) = _unverified(reader)
        assert context.check == "weak_open_check"
        assert context.reason == "partial_read"
        assert context.member_name == "stored.txt"
        assert context.to_dict()["kind"] == "encrypted_verification"
        assert _unverified_message(reader) == (
            "Encrypted ZIP member 'stored.txt' was closed before its integrity check "
            "was reached, and the password was accepted on a weaker check: the bytes "
            "read may have been decrypted with a wrong password."
        )

        # Proof it was the wrong key and not a quirk of the read: to EOF, the CRC fails.
        with pytest.raises(EncryptionError):
            reader.read(member)


def test_correct_single_zipcrypto_password_partial_read_is_reported_too() -> None:
    # One password and a one-byte check: nothing tells a right key from a colliding one.
    with open_archive(_COLLISION, password="secret") as reader:
        with reader.open(_member(reader, "stored.txt")) as stream:
            assert stream.read(5) == _plaintext("stored.txt")[:5]
        assert len(_unverified(reader)) == 1


def test_zipcrypto_read_to_eof_is_not_reported() -> None:
    with open_archive(_COLLISION, password="secret") as reader:
        for name in ("stored.txt", "deflated.txt"):
            with reader.open(_member(reader, name)) as stream:
                while stream.read(1000):
                    pass
        assert _unverified(reader) == []


def test_open_and_close_without_reading_is_not_reported() -> None:
    with open_archive(_COLLISION, password="secret") as reader:
        with reader.open(_member(reader, "stored.txt")):
            pass
        assert _unverified(reader) == []


def test_crc_confirmed_candidate_partial_read_is_not_reported() -> None:
    # Two candidates: the STORED shared pass confirms "secret" against the CRC, so the
    # partial read that follows restates nothing the caller does not know.
    with open_archive(_COLLISION, password=[_STORED_COLLISION, "secret"]) as reader:
        with reader.open(_member(reader, "stored.txt")) as stream:
            assert stream.read(5) == _plaintext("stored.txt")[:5]
        assert _unverified(reader) == []


def test_compressed_member_inside_the_prefix_confirms_on_its_crc() -> None:
    # deflated.txt is smaller than the confirm prefix: its CRC decides, so the winner
    # is CONFIRMED and a partial read is not reported.
    with open_archive(_COLLISION, password=["wrong173", "secret"]) as reader:
        member = _member(reader, "deflated.txt")
        with reader.open(member) as stream:
            assert stream.read(3) == _plaintext("deflated.txt")[:3]
        assert _unverified(reader) == []


def test_strict_collects_and_pedantic_raises() -> None:
    assert _CODE not in ARCHIVE_INTEGRITY_CODES
    with open_archive(
        _COLLISION,
        password="secret",
        config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.STRICT),
    ) as reader:
        with reader.open(_member(reader, "stored.txt")) as stream:
            stream.read(1)
        assert len(_unverified(reader)) == 1

    with open_archive(
        _COLLISION,
        password="secret",
        config=ArchiveyConfig(diagnostic_policy=DiagnosticPolicy.PEDANTIC),
    ) as reader:
        stream = reader.open(_member(reader, "stored.txt"))
        stream.read(1)
        with pytest.raises(DiagnosticRaisedError):
            stream.close()


def test_extraction_never_reports(tmp_path: Path) -> None:
    with open_archive(_COLLISION, password="secret") as reader:
        reader.extract_all(tmp_path)
        assert _unverified(reader) == []


def test_unencrypted_partial_read_is_not_reported(tmp_path: Path) -> None:
    import zipfile

    plain = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain, "w") as zf:
        zf.writestr("a.txt", b"x" * 10000)
    with open_archive(plain) as reader:
        with reader.open(_member(reader, "a.txt")) as stream:
            stream.read(1)
        assert _unverified(reader) == []


@requires("cryptography")
def test_winzip_aes_partial_read_is_reported() -> None:
    # pw_verify is two bytes (2⁻¹⁶); the HMAC at EOF is the check a partial read skips.
    with open_archive(_AE1, password="secret") as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            stream.read(1)
        (context,) = _unverified(reader)
        assert context.check == "weak_open_check"


@requires("cryptography")
def test_winzip_aes_seek_then_full_read_is_not_reported() -> None:
    # A seek does not give up the HMAC: reading on to EOF completes it over the
    # skipped ciphertext, so the password is checked and nothing is reported.
    with open_archive(_AE1, password="secret", seekable_members=True) as reader:
        member = next(m for m in reader.members() if m.is_file)
        with reader.open(member) as stream:
            stream.seek(1)
            assert stream.read()
        assert _unverified(reader) == []


@requires("cryptography")
def test_winzip_aes_seek_then_partial_read_is_reported_as_a_partial_read() -> None:
    with open_archive(_AE1, password="secret", seekable_members=True) as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert member.size is not None and member.size > 2
        with reader.open(member) as stream:
            stream.seek(1)
            assert stream.read(1)
        (context,) = _unverified(reader)
        assert context.check == "weak_open_check"
        assert context.reason == "partial_read"


@requires("cryptography")
def test_winzip_aes_full_read_is_not_reported() -> None:
    with open_archive(_AE1, password="secret") as reader:
        member = next(m for m in reader.members() if m.is_file)
        reader.read(member)
        assert _unverified(reader) == []


@requires_binary("zip")
def test_large_compressed_member_ambiguous_candidates_budget_exhausted(
    tmp_path: Path,
) -> None:
    # A DEFLATE member past the confirm prefix: the survivor is INCONCLUSIVE, so a
    # partial read is reported with the budget as the reason.
    src = tmp_path / "big.txt"
    words = [b"alpha", b"bravo", b"charlie", b"delta"]
    src.write_bytes(b" ".join(words[(i * 7) % 4] for i in range(60000)))
    archive = tmp_path / "big.zip"
    result = subprocess.run(
        ["zip", "-q", "-P", "secret", "-9", str(archive), src.name],
        cwd=tmp_path,
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("zip CLI could not build the fixture")
    with open_archive(archive, password=["nope", "secret"]) as reader:
        with reader.open(_member(reader, "big.txt")) as stream:
            assert stream.read(5) == src.read_bytes()[:5]
        (context,) = _unverified(reader)
        assert context.check == "confirm_budget_exhausted"
        # A survivor of an ambiguous set without a CRC match stays out of known-good.
        assert reader._passwords._known_good == []


# --- RAR ---------------------------------------------------------------------------
#
# RAR3/4 encrypted data carries no password check value, so nothing vouches for a
# password before ``unrar`` decodes with it; only the CRC at the member's end does.
# A wrong key does not reliably stop ``unrar`` before output: measured on unrar 7.00,
# about three wrong passwords in ten decode a compressed member into bytes it streams
# before the CRC fails (a stored member always does). These wrong passwords are ones
# that do, for the named members (dev-docs/formats/rar.md §2.2).
_RAR4 = _FIXTURES / "rar" / "encryption__rar4.rar"
_RAR4_LEAKING_WRONG = "wrong3"  # secret.txt: 14 bytes out, exit 3
_RAR4_SOLID = _FIXTURES / "external" / "rar4_solid_encrypted_libarchive.rar"
_RAR4_SOLID_LEAKING_WRONG = "wrong0"  # a.txt: 18 bytes out, exit 3
_RAR_SECRET = b"This is secret"


@requires_binary("unrar")
def test_rar4_wrong_password_partial_read_is_reported() -> None:
    with open_archive(_RAR4, password=_RAR4_LEAKING_WRONG) as reader:
        member = _member(reader, "secret.txt")
        with reader.open(member) as stream:
            # The wrong key reaches the read and returns bytes that are not the
            # member's; nothing has checked them yet.
            head = stream.read(4)
        assert len(head) == 4 and head != _RAR_SECRET[:4]
        (context,) = _unverified(reader)
        assert context.check == "no_password_check"
        assert context.reason == "partial_read"
        assert context.member_name == "secret.txt"
        assert _unverified_message(reader) == (
            "Encrypted RAR member 'secret.txt' was closed before its checksum was "
            "reached, and it carries no password check: the bytes read may have been "
            "decrypted with a wrong password."
        )

        # Proof it was the wrong key: to EOF, the CRC fails.
        with pytest.raises((EncryptionError, CorruptionError)):
            reader.read(member)


@requires_binary("unrar")
def test_rar4_correct_password_partial_read_is_reported_too() -> None:
    # No check value: nothing tells the right key from a wrong one before the CRC.
    with open_archive(_RAR4, password="password") as reader:
        with reader.open(_member(reader, "secret.txt")) as stream:
            assert stream.read(4) == _RAR_SECRET[:4]
        assert len(_unverified(reader)) == 1


@requires_binary("unrar")
def test_rar4_read_to_eof_is_not_reported() -> None:
    with open_archive(_RAR4, password="password") as reader:
        for name in ("secret.txt", "also_secret.txt"):
            with reader.open(_member(reader, name)) as stream:
                stream.read()
        assert _unverified(reader) == []


@requires_binary("unrar")
def test_rar4_seek_then_partial_read_is_reported_as_a_partial_read() -> None:
    # The bytes the forward seek skips must be decoded anyway (unrar's pipe), so the
    # next read hashes them and the CRC is kept: what misses it is closing early.
    with open_archive(_RAR4, password="password", seekable_members=True) as reader:
        with reader.open(_member(reader, "secret.txt")) as stream:
            stream.seek(8)
            assert stream.read(2) == _RAR_SECRET[8:10]
        (context,) = _unverified(reader)
        assert context.reason == "partial_read"
        assert _unverified_message(reader) == (
            "Encrypted RAR member 'secret.txt' was closed before its checksum was "
            "reached, and it carries no password check: the bytes read may have been "
            "decrypted with a wrong password."
        )


@requires_binary("unrar")
def test_rar4_seek_then_read_to_eof_is_not_reported() -> None:
    with open_archive(_RAR4, password="password", seekable_members=True) as reader:
        with reader.open(_member(reader, "secret.txt")) as stream:
            stream.seek(8)
            assert stream.read() == _RAR_SECRET[8:]
        assert _unverified(reader) == []


@requires_binary("unrar")
def test_rar4_solid_pass_partial_read_is_reported() -> None:
    # The solid pass demultiplexes one ``unrar p`` run; its members are watched too.
    with open_archive(_RAR4_SOLID, password=_RAR4_SOLID_LEAKING_WRONG) as reader:
        # Closed, not dropped: PyPy would close a dropped pass only when collected.
        with contextlib.closing(reader.stream_members()) as passing:
            for member, stream in passing:
                assert stream is not None
                head = stream.read(4)
                assert len(head) == 4 and head != b"This"
                break
        (context,) = _unverified(reader)
        assert context.member_name == "a.txt"
        assert context.check == "no_password_check"


@requires_binary("unrar")
def test_rar4_solid_pass_read_to_eof_is_not_reported() -> None:
    with open_archive(_RAR4_SOLID, password="password") as reader:
        for _member_, stream in reader.stream_members():
            assert stream is not None
            assert stream.read().startswith(b"This is from ")
        assert _unverified(reader) == []


@requires("cryptography")
@requires_binary("unrar")
@pytest.mark.parametrize(
    ("name", "password"),
    [
        # RAR5: the record's 64-bit PswCheck accepted the password before unrar ran.
        ("encryption_stored__.rar", "password"),
        ("encryption__.rar", "password"),
        # RAR4 -hp: the password decrypted every header past its CRC.
        ("encrypted_header__rar4.rar", "header_password"),
    ],
)
def test_rar_checked_password_partial_read_is_not_reported(
    name: str, password: str
) -> None:
    with open_archive(_FIXTURES / "rar" / name, password=password) as reader:
        member = next(m for m in reader.members() if m.is_file and m.size)
        with reader.open(member) as stream:
            assert stream.read(2)
        assert _unverified(reader) == []
