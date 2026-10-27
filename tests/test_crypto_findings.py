"""Regression coverage for PR #115 crypto findings (F1–F5).

F1 — RAR5 tweaked checksums (HASHMAC): drop from ``member.hashes``, stash in
     ``extra``, forward-transform verify when a password is available.
F2 — Encrypted 7z with no integrity anchor: best-effort accept + diagnostic.
F3 — Cap 7z ``NumCyclesPower`` at 24 (or ``0x3F``), matching 7-Zip.
F4 — Pass ``unrar`` password via bare ``-p`` + stdin (not argv).
F5 — ``hmac.compare_digest`` for RAR5 PswCheck.
"""

from __future__ import annotations

import hashlib
import io
import zlib
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.diagnostics import DiagnosticCode
from archivey.exceptions import (
    CorruptionError,
    EncryptionError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import sevenzip_aes
from archivey.internal.backends.rar_parser import (
    RarEncryptionInfo,
    RarMemberInfo,
    _check_rar5_password,
    convert_blake2sp_to_mac,
    convert_crc_to_mac,
    parse_rar_archive,
    rar5_hash_key,
)
from archivey.internal.backends.rar_reader import _crc_is_tweaked, _member_hashes
from archivey.internal.backends.rar_unrar import (
    _password_arg,
    open_unrar_p,
)
from archivey.internal.backends.sevenzip_parser import (
    SevenZipArchive,
    SevenZipCoder,
    SevenZipFileRecord,
    SevenZipFolder,
)
from archivey.internal.backends.sevenzip_reader import SevenZipReader
from archivey.internal.diagnostics_collector import DiagnosticCollector
from archivey.internal.external.cli import terminate_process
from archivey.internal.hashing import crc32_digest
from archivey.internal.hashing.blake2sp import Blake2sp
from archivey.internal.streams.verify import VerifyingStream
from archivey.types import HashAlgorithm
from tests.conftest import requires, requires_binary
from tests.corruption_util import raises_corruption_not_truncation

_RAR = Path(__file__).parent / "fixtures" / "rar"


def _rar_fixture(name: str) -> Path:
    path = _RAR / name
    if not path.is_file():
        pytest.skip(f"missing vendored fixture {name}")
    return path


def _minimal_rar_member(
    *,
    crc32: int | None = None,
    blake2sp_hash: bytes | None = None,
    flags: int = 0x03,
) -> RarMemberInfo:
    enc = RarEncryptionInfo(
        algo=0,
        flags=flags,
        kdf_count=15,
        salt=bytes(16),
        iv=bytes(16),
        check_value=None,
    )
    return RarMemberInfo(
        filename="x.txt",
        orig_filename=b"x.txt",
        file_size=4,
        compress_size=4,
        compress_type=0x30,
        crc32=crc32,
        blake2sp_hash=blake2sp_hash,
        mtime=None,
        ctime=None,
        atime=None,
        mode=None,
        host_os=3,
        flags=0,
        file_redir=None,
        file_encryption=enc,
        header_offset=0,
        header_size=0,
        data_offset=0,
        extract_version=None,
        file_solid=False,
        is_directory=False,
        is_symlink=False,
        is_hardlink_or_copy=False,
        is_encrypted=True,
        volume_index=0,
        split_before=False,
        split_after=False,
    )


# --- F1: RAR5 tweaked checksums --------------------------------------------------------


def test_f1_member_hashes_drops_tweaked_blake2sp_and_crc32() -> None:
    """Symmetric with the pre-existing crc32 drop: tweaked blake2sp must leave hashes."""
    info = _minimal_rar_member(crc32=0xDEADBEEF, blake2sp_hash=bytes(32))
    assert _crc_is_tweaked(info)
    assert _member_hashes(info) == {}


def test_f1_member_hashes_keeps_untweaked_digests() -> None:
    info = _minimal_rar_member(
        crc32=0x11, blake2sp_hash=b"\x22" * 32, flags=0x01
    )  # checkval only
    assert not _crc_is_tweaked(info)
    assert _member_hashes(info) == {
        HashAlgorithm.CRC32: crc32_digest(0x11),
        HashAlgorithm.BLAKE2SP: b"\x22" * 32,
    }


def test_f1_convert_hash_to_mac_crc_and_blake2sp_roundtrip() -> None:
    password = b"password"
    salt = bytes(range(16))
    kdf = 15
    hash_key = rar5_hash_key(password, salt, kdf)

    plaintext = b"stored payload"
    real_crc = zlib.crc32(plaintext) & 0xFFFFFFFF
    hasher = Blake2sp()
    hasher.update(plaintext)
    real_blake = hasher.digest()

    tweaked_crc = convert_crc_to_mac(real_crc, hash_key)
    tweaked_blake = convert_blake2sp_to_mac(real_blake, hash_key)

    # Forward transform is deterministic; re-applying with the same key matches.
    assert convert_crc_to_mac(real_crc, hash_key) == tweaked_crc
    assert convert_blake2sp_to_mac(real_blake, hash_key) == tweaked_blake

    # VerifyingStream with transforms accepts good data and rejects a wrong MAC.
    transforms = {
        HashAlgorithm.CRC32: lambda d, hk=hash_key: crc32_digest(
            convert_crc_to_mac(int.from_bytes(d, "big"), hk)
        ),
        HashAlgorithm.BLAKE2SP: lambda d, hk=hash_key: convert_blake2sp_to_mac(d, hk),
    }
    expected = {
        HashAlgorithm.CRC32: crc32_digest(tweaked_crc),
        HashAlgorithm.BLAKE2SP: tweaked_blake,
    }
    stream = VerifyingStream(
        io.BytesIO(plaintext), expected, digest_transforms=transforms
    )
    assert stream.read() == plaintext
    stream.close()

    bad = VerifyingStream(
        io.BytesIO(plaintext),
        {HashAlgorithm.BLAKE2SP: bytes(32)},
        digest_transforms=transforms,
    )
    with raises_corruption_not_truncation(match="blake2sp"):
        bad.read()
        bad.close()


@pytest.mark.parametrize(
    ("fixture", "member_name", "plaintext", "kind"),
    [
        ("encryption__.rar", "secret.txt", b"This is secret", "crc32"),
        ("encryption__.rar", "also_secret.txt", b"This is also secret", "crc32"),
        ("encryption_blake2sp.rar", "store.txt", b"stored payload", "blake2sp"),
    ],
)
def test_f1_convert_hash_to_mac_matches_fixture_stored_digest(
    fixture: str, member_name: str, plaintext: bytes, kind: str
) -> None:
    """Bit-exact ConvertHashToMAC vs vendored fixtures — no ``unrar`` required.

    Parses metadata with the native RAR parser, recomputes the plaintext digest, applies
    the forward transform with the fixture password/salt/kdf, and compares to the stored
    (already tweaked) value. Catches transform drift on CI legs that skip the e2e reads.
    """
    path = _rar_fixture(fixture)
    with path.open("rb") as handle:
        info = next(
            m for m in parse_rar_archive(handle).members if m.filename == member_name
        )
    assert info.file_encryption is not None
    assert _crc_is_tweaked(info)
    enc = info.file_encryption
    hash_key = rar5_hash_key("password", enc.salt, enc.kdf_count)

    if kind == "crc32":
        assert info.crc32 is not None
        real_crc = zlib.crc32(plaintext) & 0xFFFFFFFF
        assert convert_crc_to_mac(real_crc, hash_key) == info.crc32
    else:
        assert info.blake2sp_hash is not None
        hasher = Blake2sp()
        hasher.update(plaintext)
        assert convert_blake2sp_to_mac(hasher.digest(), hash_key) == info.blake2sp_hash


@requires_binary("unrar")
def test_f1_encryption_fixture_stashes_tweaked_crc_and_reads() -> None:
    path = _rar_fixture("encryption__.rar")
    with path.open("rb") as handle:
        archive = parse_rar_archive(handle)
    secret = next(m for m in archive.members if m.filename == "secret.txt")
    assert _crc_is_tweaked(secret)
    assert secret.crc32 is not None
    assert _member_hashes(secret) == {}

    with open_archive(path, password="password") as reader:
        member = next(m for m in reader.members() if m.name == "secret.txt")
        assert member.hashes == {}
        assert member.extra["rar.tweaked_crc32"] == secret.crc32
        assert reader.read(member) == b"This is secret"


@requires_binary("unrar")
def test_f1_encryption_blake2sp_reads_without_false_corruption() -> None:
    """The F1 bug: tweaked blake2sp in hashes → CorruptionError on good data."""
    path = _rar_fixture("encryption_blake2sp.rar")
    with path.open("rb") as handle:
        info = parse_rar_archive(handle).members[0]
    assert info.blake2sp_hash is not None
    assert _crc_is_tweaked(info)
    # Pre-fix asymmetry would have kept blake2sp; post-fix drops it.
    assert _member_hashes(info) == {}

    with open_archive(path, password="password") as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert HashAlgorithm.BLAKE2SP not in member.hashes
        assert member.extra["rar.tweaked_blake2sp"] == info.blake2sp_hash
        assert reader.read(member) == b"stored payload"
        # Password known → forward-transform verify; no DIGEST_UNVERIFIABLE.
        assert reader.diagnostics.counts.get(DiagnosticCode.DIGEST_UNVERIFIABLE, 0) == 0


@requires_binary("unrar")
def test_f1_tweaked_without_password_emits_digest_unverifiable() -> None:
    path = _rar_fixture("encryption_blake2sp.rar")
    with open_archive(path) as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert member.hashes == {}
        assert DiagnosticCode.DIGEST_UNVERIFIABLE in reader.diagnostics.counts
        reasons = [
            d.context.reason
            for d in reader.diagnostics.retained
            if d.code is DiagnosticCode.DIGEST_UNVERIFIABLE
        ]
        assert "tweaked_checksum" in reasons


@requires_binary("unrar")
def test_f1_forward_transform_detects_corrupt_tweaked_blake2sp() -> None:
    """With a password, ConvertHashToMAC must still catch a flipped stored digest.

    On-disk flips also break the RAR5 header CRC, so open a good archive and
    replace the member's stored blake2sp before reading.
    """
    from dataclasses import replace

    path = _rar_fixture("encryption_blake2sp.rar")
    with open_archive(path, password="password") as reader:
        member = next(m for m in reader.members() if m.is_file)
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        member._raw = replace(raw, blake2sp_hash=bytes(32))
        with raises_corruption_not_truncation(match="blake2sp"):
            reader.read(member)


# --- F2: 7z no-anchor encrypted folder -------------------------------------------------


# The confirm walk itself (earliest anchor, short reads, bounded chunks) is unit-tested
# in tests/test_password_confirm.py, against the shared planner and runner.


def test_f2_no_anchor_encrypted_member_emits_diagnostic() -> None:
    collector = DiagnosticCollector()
    reader = object.__new__(SevenZipReader)
    reader._archive_name = "no-anchor.7z"
    reader._diagnostics_collector = collector
    folder = SevenZipFolder(
        coders=[
            SevenZipCoder(
                method=b"\x06\xf1\x07\x01",
                num_in_streams=1,
                num_out_streams=1,
                properties=b"\xc0\x00\x00\x00",
            )
        ],
        bind_pairs=[],
        packed_indices=[0],
        unpack_sizes=[4],
        crc=None,
        digest_defined=False,
    )
    reader._archive = SevenZipArchive(
        major_version=0,
        minor_version=4,
        pack_pos=0,
        pack_sizes=[4],
        pack_positions=[0],
        folders=[folder],
        num_unpackstreams_folders=[1],
        unpack_sizes=[4],
        digests=[None],
        files=[],
        comment=None,
        is_solid=False,
        is_header_encrypted=False,
        has_encrypted_folders=True,
        end_offset=4,
    )
    reader._init_folder_caches(reader._archive)
    record = SevenZipFileRecord(
        filename="store.txt",
        emptystream=False,
        is_anti=False,
        is_directory=False,
        attributes=None,
        creation_time=None,
        last_access_time=None,
        last_write_time=None,
        folder_index=0,
        file_in_folder=0,
        uncompressed_size=4,
        crc32=None,
        compressed_size=4,
        is_encrypted=True,
    )
    member = reader._to_member(record, 0)
    assert member.hashes == {}
    summary = collector.snapshot()
    assert summary.counts.get(DiagnosticCode.DIGEST_UNVERIFIABLE, 0) == 1
    assert summary.retained[0].context.reason == "no_integrity_anchor"


@requires("cryptography")
@requires("py7zr")
def test_f2_normal_aes_archive_has_crc_anchor_no_diagnostic(tmp_path: Path) -> None:
    """Ordinary py7zr-encrypted archives carry CRCs — no F2 diagnostic."""
    from tests.test_sevenzip_reader import _write_py7zr_archive

    archive = tmp_path / "aes.7z"
    _write_py7zr_archive(archive, {"a.txt": b"hello"}, password="secret")
    with open_archive(archive, password="secret") as reader:
        member = next(m for m in reader.members() if m.is_file)
        assert HashAlgorithm.CRC32 in member.hashes
        assert reader.diagnostics.counts.get(DiagnosticCode.DIGEST_UNVERIFIABLE, 0) == 0
        assert reader.read(member) == b"hello"


# --- F3: 7z NumCyclesPower cap ---------------------------------------------------------


@requires("cryptography")
@pytest.mark.parametrize("cycles", [0, 1, 19, 24, 0x3F])
def test_f3_accepted_num_cycles_power(cycles: int) -> None:
    key = sevenzip_aes.derive_sevenzip_aes_key(b"pw", salt=b"salt", cycles=cycles)
    assert len(key) == 32


@requires("cryptography")
@pytest.mark.parametrize("cycles", [25, 40, 62])
def test_f3_rejected_num_cycles_power(cycles: int) -> None:
    with pytest.raises(UnsupportedFeatureError, match="NumCyclesPower"):
        sevenzip_aes.derive_sevenzip_aes_key(b"pw", salt=b"salt", cycles=cycles)


@requires("cryptography")
@pytest.mark.parametrize("cycles", [25, 62])
def test_f3_parse_properties_rejects_hostile_cycles(cycles: int) -> None:
    # first byte: salt+IV flags in high bits, cycles in low 6 bits; second: sizes 0/0
    # Use salt_size=0, iv_size=0 via first=0xC0|cycles and second=0x00 — but salt/IV
    # flags require at least the flag bits. Minimal: first = 0xC0 | cycles, second = 0
    # → salt_size=1, iv_size=1, then 2 zero bytes.
    first = 0xC0 | cycles
    properties = bytes([first, 0x00, 0x00, 0x00])
    with pytest.raises(UnsupportedFeatureError, match="NumCyclesPower"):
        sevenzip_aes.parse_sevenzip_aes_properties(properties)


@requires("cryptography")
def test_f3_parse_properties_allows_0x3f_sentinel() -> None:
    properties = bytes([0xC0 | 0x3F, 0x00, 0x00, 0x00])
    cycles, salt, iv = sevenzip_aes.parse_sevenzip_aes_properties(properties)
    assert cycles == 0x3F
    assert len(salt) == 1 and len(iv) == 16


@pytest.mark.parametrize("first", [0x00, 0x13, 0x3F])
def test_parse_properties_accepts_one_byte_without_salt_or_iv(first: int) -> None:
    """7-Zip and py7zr take a flagless one-byte blob as no salt and a zero IV."""
    cycles, salt, iv = sevenzip_aes.parse_sevenzip_aes_properties(bytes([first]))
    assert cycles == first
    assert salt == b""
    assert iv == bytes(16)


def test_parse_properties_refuses_trailing_bytes_without_flags() -> None:
    with pytest.raises(ValueError, match="no salt or IV flags"):
        sevenzip_aes.parse_sevenzip_aes_properties(b"\x13\x00")


@requires("cryptography")
def test_f3_out_of_range_still_value_error() -> None:
    with pytest.raises(ValueError, match="out of range"):
        sevenzip_aes.derive_sevenzip_aes_key(b"pw", salt=b"s", cycles=0x40)
    with pytest.raises(ValueError, match="out of range"):
        sevenzip_aes.derive_sevenzip_aes_key(b"pw", salt=b"s", cycles=-1)


# --- F4: unrar password via stdin ------------------------------------------------------


def test_f4_password_arg_is_bare_or_dash() -> None:
    assert _password_arg(None) == "-p-"
    assert _password_arg("") == "-p-"
    assert _password_arg(b"") == "-p-"
    assert _password_arg("secret") == "-p"
    assert _password_arg(b"secret") == "-p"
    # Must not embed the password in the switch value.
    assert "secret" not in _password_arg("secret")


@requires_binary("unrar")
def test_f4_password_passed_via_stdin_not_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    """Spy on Popen: argv gets bare ``-p``, password bytes go to stdin (race-free)."""
    import subprocess

    from archivey.internal.backends import rar_unrar

    captured: dict[str, object] = {}
    real_popen = subprocess.Popen

    def spy_popen(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
        captured["cmd"] = list(cmd)
        captured["stdin"] = kwargs.get("stdin")
        proc = real_popen(cmd, *args, **kwargs)
        if kwargs.get("stdin") is subprocess.PIPE and proc.stdin is not None:
            # open_unrar_p writes the password after Popen returns; wrap write.
            real_write = proc.stdin.write

            def noting_write(data: bytes) -> int:
                captured["stdin_bytes"] = data
                return real_write(data)

            proc.stdin.write = noting_write  # type: ignore[method-assign]
        return proc

    monkeypatch.setattr(rar_unrar.subprocess, "Popen", spy_popen)

    path = _rar_fixture("encryption__.rar")
    proc, stdout = open_unrar_p(path, password="password", member="secret.txt")
    try:
        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        assert "-p" in cmd
        assert "-ppassword" not in cmd
        assert not any(
            isinstance(part, str) and "password" in part and part != "-p"
            for part in cmd
        )
        assert captured["stdin"] is subprocess.PIPE
        assert captured.get("stdin_bytes") == b"password\n"
        assert stdout.read() == b"This is secret"
    finally:
        stdout.close()
        terminate_process(proc)


@requires_binary("unrar")
def test_f4_stdin_password_wrong_still_fails() -> None:
    path = _rar_fixture("encryption__.rar")
    with (
        open_archive(path, password="wrong") as reader,
        pytest.raises((EncryptionError, CorruptionError)),
    ):
        reader.read("secret.txt")


@requires_binary("unrar")
def test_f4_unencrypted_still_uses_p_dash(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from archivey.internal.backends import rar_unrar

    captured: dict[str, object] = {}
    real_popen = subprocess.Popen

    def spy_popen(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
        captured["cmd"] = list(cmd)
        captured["stdin"] = kwargs.get("stdin")
        return real_popen(cmd, *args, **kwargs)

    monkeypatch.setattr(rar_unrar.subprocess, "Popen", spy_popen)

    path = _rar_fixture("blake2sp.rar")
    proc, stdout = open_unrar_p(path, password=None, member="store.txt")
    try:
        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        assert "-p-" in cmd
        assert captured["stdin"] is subprocess.DEVNULL
        assert stdout.read() == b"stored payload"
    finally:
        stdout.close()
        terminate_process(proc)


# --- F5: compare_digest for RAR5 password check ----------------------------------------


def test_f5_check_rar5_password_accepts_and_rejects() -> None:
    """Build a valid PswCheck blob and confirm compare_digest path works both ways."""
    password = "header_password"
    salt = bytes(range(16))
    kdf_shift = 15
    # PswCheck material at (1<<kdf)+32, XOR-folded to 8 bytes (same as parser).
    from archivey.internal.backends.rar_parser import _rar5_s2k

    pwd_hash = _rar5_s2k(password, salt, (1 << kdf_shift) + 32)
    pwd_check = bytearray(8)
    for i, value in enumerate(pwd_hash):
        pwd_check[i & 7] ^= value
    hdr_check = bytes(pwd_check)
    hdr_sum = hashlib.sha256(hdr_check).digest()[:4]
    check_value = hdr_check + hdr_sum

    assert _check_rar5_password(check_value, kdf_shift, salt, password) is True
    with pytest.raises(EncryptionError, match="Wrong password"):
        _check_rar5_password(check_value, kdf_shift, salt, "nope")


@requires("cryptography")
@requires_binary("unrar")
def test_f5_encrypted_header_fixture_still_opens() -> None:
    path = _rar_fixture("encrypted_header__.rar")
    with open_archive(path, password="header_password") as reader:
        assert reader.read("file1.txt") == b"Hello, world!"
    with pytest.raises(EncryptionError):
        open_archive(path, password="wrong")
