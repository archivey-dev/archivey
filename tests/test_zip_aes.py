"""WinZip AES (AE-1 / AE-2) ZIP member decryption tests."""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import io
import os
import random
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

from archivey import open_archive
from archivey.config import AcceleratorMode, ArchiveyConfig
from archivey.exceptions import (
    CorruptionError,
    EncryptionError,
    PackageNotInstalledError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal.backends import zip_aes
from archivey.internal.backends.zip_aes import (
    ExtraField,
    WinZipAesDecryptStream,
    WinZipAesForwardStream,
    WinZipAesInfo,
    derive_winzip_aes_keys,
    iter_extra_fields,
    open_winzip_aes_forward,
    open_winzip_aes_member,
    parse_winzip_aes_extra,
    split_extra_fields,
)
from archivey.internal.streams import codecs
from archivey.internal.streams.streamtools.binaryio import source_byte_size
from archivey.types import CompressionAlgorithm, HashAlgorithm
from tests.conftest import requires, requires_binary
from tests.corruption_util import raises_corruption_not_truncation
from tests.zip_aes_fixture import aes_ctr_le_encrypt, build_aes_zip

_PASSWORD = b"secret"
_PAYLOAD = b"winzip-aes-payload\n" * 40


def _build_aes_zip(
    *,
    payload: bytes,
    password: bytes,
    vendor_version: int,
    strength: int,
    method: int,
    name: bytes = b"secret.txt",
    tamper_hmac: bool = False,
) -> bytes:
    """Single-entry wrapper around the shared AES ZIP builder."""
    return build_aes_zip(
        [(name, payload)],
        password=password,
        vendor_version=vendor_version,
        strength=strength,
        method=method,
        tamper_hmac=tamper_hmac,
    )


def _7z_aes_zip(tmp_path: Path, *, strength: str = "AES256") -> tuple[Path, bytes]:
    payload = _PAYLOAD + os.urandom(32)
    src = tmp_path / "payload.bin"
    src.write_bytes(payload)
    archive = tmp_path / f"aes_{strength}.zip"
    result = subprocess.run(
        [
            "7z",
            "a",
            "-tzip",
            f"-mem={strength}",
            f"-p{_PASSWORD.decode()}",
            str(archive),
            src.name,
            "-y",
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not archive.is_file():
        pytest.skip(f"7z cannot write AES ZIP: {result.stderr}")
    with zipfile.ZipFile(archive) as zf:
        info = zf.infolist()[0]
        if info.compress_type != 99:
            pytest.skip(f"7z did not emit method 99 (got {info.compress_type})")
    return archive, payload


@requires("cryptography")
@pytest.mark.parametrize(
    ("vendor_version", "strength", "method"),
    [
        (1, 1, 0),  # AE-1, 128, STORED
        (1, 3, 8),  # AE-1, 256, DEFLATE
        (2, 1, 0),  # AE-2, 128, STORED
        (2, 3, 8),  # AE-2, 256, DEFLATE
        (2, 2, 8),  # AE-2, 192, DEFLATE
    ],
)
def test_handbuilt_aes_roundtrip(
    vendor_version: int, strength: int, method: int
) -> None:
    data = _build_aes_zip(
        payload=_PAYLOAD,
        password=_PASSWORD,
        vendor_version=vendor_version,
        strength=strength,
        method=method,
    )
    with open_archive(io.BytesIO(data), password=_PASSWORD) as ar:
        (member,) = ar.members()
        assert member.is_encrypted
        assert member.extra["zip.aes_vendor_version"] == vendor_version
        assert member.extra["zip.aes_strength"] == strength
        if vendor_version == 2:
            assert HashAlgorithm.CRC32 not in member.hashes
        else:
            assert HashAlgorithm.CRC32 in member.hashes
        expected_algo = (
            CompressionAlgorithm.STORED if method == 0 else CompressionAlgorithm.DEFLATE
        )
        assert member.compression[0].algo is expected_algo
        assert ar.read(member) == _PAYLOAD


@requires_binary("7z")
@requires("cryptography")
@pytest.mark.parametrize("strength", ["AES128", "AES256"])
def test_7z_aes_zip_roundtrip(tmp_path: Path, strength: str) -> None:
    archive, payload = _7z_aes_zip(tmp_path, strength=strength)
    with open_archive(archive, password=_PASSWORD) as ar:
        (member,) = ar.members()
        assert member.is_encrypted
        assert HashAlgorithm.CRC32 not in member.hashes  # 7z emits AE-2
        assert ar.read(member) == payload


_EXTERNAL_DIR = Path(__file__).parent / "fixtures" / "external"


def _patch_stored_crc(data: bytes, value: int) -> bytes:
    """Rewrite both copies of the CRC in a single-member `_build_aes_zip` output.

    The LFH is at offset 0 and the central directory starts where the EOCD says, so
    this only holds for the one-entry archives built above.
    """
    buf = bytearray(data)
    eocd = buf.rindex(b"PK\x05\x06")
    offset_cd = struct.unpack_from("<I", buf, eocd + 16)[0]
    struct.pack_into("<I", buf, 14, value)
    struct.pack_into("<I", buf, offset_cd + 16, value)
    return bytes(buf)


@requires_binary("7z")
@requires("cryptography")
def test_handbuilt_ae1_is_accepted_by_7z(tmp_path: Path) -> None:
    """Cross-check the AE-1 builder against an independent implementation.

    7-Zip writes AE-2, so `test_7z_aes_zip_roundtrip` cannot reach AE-1: without this,
    every AE-1 fixture in the suite is bytes we assembled and then read back ourselves.
    7-Zip *reads* AE-1 and checks its CRC, so accepting our fixture validates the key
    derivation, the CTR keystream, the HMAC and the AE-1 CRC rule in one verdict.

    The two corrupted-CRC cases are the control: they are what makes the pass mean
    something, and they pin the asymmetry the AE-1/AE-2 split is about — 7-Zip rejects a
    wrong CRC on AE-1 and ignores one on AE-2.
    """
    archive = tmp_path / "ae1.zip"

    def check_7z(payload: bytes) -> int:
        archive.write_bytes(payload)
        return subprocess.run(
            ["7z", "t", f"-p{_PASSWORD.decode()}", str(archive)],
            capture_output=True,
            text=True,
            check=False,
        ).returncode

    ae1 = _build_aes_zip(
        payload=_PAYLOAD, password=_PASSWORD, vendor_version=1, strength=3, method=8
    )
    ae2 = _build_aes_zip(
        payload=_PAYLOAD, password=_PASSWORD, vendor_version=2, strength=3, method=8
    )
    assert check_7z(ae1) == 0
    assert check_7z(ae2) == 0
    assert check_7z(_patch_stored_crc(ae1, 0xDEADBEEF)) != 0
    assert check_7z(_patch_stored_crc(ae2, 0xDEADBEEF)) == 0


@requires("cryptography")
def test_external_ae1_archive_from_pyzipper() -> None:
    """A third-party AE-1 member, not one of ours.

    `pyzipper` 0.3.0 (2019) through 0.3.6 (2022) wrote AE-1 for every AES member
    regardless of size, and 0.3.6 was the only release available until 0.4.0 switched to
    AE-2 in 2026 — so AE-1 is real traffic, not a legacy branch. See
    `tests/fixtures/external/README.md`.
    """
    with open_archive(
        _EXTERNAL_DIR / "aes_ae1_pyzipper036.zip", password=_PASSWORD
    ) as ar:
        (member,) = ar.members()
        assert member.is_encrypted
        assert member.extra["zip.aes_vendor_version"] == 1
        assert HashAlgorithm.CRC32 in member.hashes  # AE-1 keeps the plaintext CRC
        assert ar.read(member) == b"AE-1 keeps the plaintext CRC in the header.\n"


@requires("cryptography")
def test_aes_wrong_password_fails_fast() -> None:
    data = _build_aes_zip(
        payload=_PAYLOAD, password=_PASSWORD, vendor_version=2, strength=3, method=8
    )
    with (
        open_archive(io.BytesIO(data), password=b"wrong") as ar,
        pytest.raises(EncryptionError, match="Wrong password"),
    ):
        ar.read(ar.members()[0])


@pytest.mark.parametrize("method", [0, 8], ids=["stored", "deflate"])
@requires("cryptography")
def test_aes_tampered_hmac_raises_corruption(method: int) -> None:
    data = _build_aes_zip(
        payload=_PAYLOAD,
        password=_PASSWORD,
        vendor_version=2,
        strength=3,
        method=method,
        tamper_hmac=True,
    )
    with (
        open_archive(io.BytesIO(data), password=_PASSWORD) as ar,
        raises_corruption_not_truncation(match="HMAC"),
    ):
        ar.read(ar.members()[0])


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
@requires("cryptography")
def test_aes_hmac_mismatch_keeps_raising_after_a_seek_back(method: int) -> None:
    """After the HMAC fails, seeking back and re-reading raises it again (S28-K1)."""
    data = _build_aes_zip(
        payload=_PAYLOAD,
        password=_PASSWORD,
        vendor_version=2,
        strength=3,
        method=method,
        tamper_hmac=True,
    )
    with (
        open_archive(io.BytesIO(data), password=_PASSWORD, seekable_members=True) as ar,
        ar.open(ar.members()[0]) as stream,
    ):
        with raises_corruption_not_truncation(match="HMAC"):
            stream.read()
        stream.seek(0)
        with raises_corruption_not_truncation(match="HMAC"):
            stream.read()
        # Asking for exactly the member returns in full, and still raises.
        stream.seek(0)
        with raises_corruption_not_truncation(match="HMAC"):
            stream.read(len(_PAYLOAD))


@requires("cryptography")
def test_aes_stage_read_none_reads_to_the_hmac() -> None:
    """``read(None)`` on the decrypt stage reads to the end and checks the HMAC (S28-K3)."""
    data = _build_aes_zip(
        payload=_PAYLOAD,
        password=_PASSWORD,
        vendor_version=2,
        strength=3,
        method=zipfile.ZIP_STORED,
        tamper_hmac=True,
    )
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        info = zf.infolist()[0]
        aes = parse_winzip_aes_extra(info.extra)
        assert aes is not None
        (name_len, extra_len) = struct.unpack_from("<HH", data, info.header_offset + 26)
        start = info.header_offset + 30 + name_len + extra_len
    raw = io.BytesIO(data[start : start + info.compress_size])
    stream = open_winzip_aes_member(
        raw, aes=aes, password=_PASSWORD, compress_size=info.compress_size
    )
    with raises_corruption_not_truncation(match="HMAC"):
        stream.read(None)


@pytest.mark.parametrize("mode", [AcceleratorMode.AUTO, AcceleratorMode.ON])
@pytest.mark.parametrize("passwords", [[_PASSWORD], [b"other", _PASSWORD]])
@requires("cryptography", "rapidgzip")
def test_aes_hmac_survives_a_seekable_accelerator(
    mode: AcceleratorMode, passwords: list[bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An accelerator that seeks its input does not void the HMAC.

    With ``seekable_members=True`` the decrypt stage is seekable, and rapidgzip reads
    its source out of order. The HMAC is the only check on an AE-2 member and the
    confirmation for several candidates, so a caller who reads straight through gets
    its verdict whatever the codec layer does underneath.
    """
    moving_seeks: list[int] = []
    real_seek = WinZipAesDecryptStream.seek

    def spy_seek(self: WinZipAesDecryptStream, offset: int, whence: int = 0) -> int:
        before = self.tell()
        result = real_seek(self, offset, whence)
        if result != before:
            moving_seeks.append(result)
        return result

    monkeypatch.setattr(WinZipAesDecryptStream, "seek", spy_seek)
    # The shipped AUTO threshold is 16 MiB; lowered so AUTO reaches rapidgzip here.
    monkeypatch.setattr(
        codecs.rapidgzip_select, "RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE", 1 << 20
    )
    config = ArchiveyConfig(use_rapidgzip=mode)
    # Incompressible and over the lowered AUTO threshold, which sees the stage's size.
    payload = random.Random(480).randbytes(1_200_000)
    for tamper in (False, True):
        data = _build_aes_zip(
            payload=payload,
            password=_PASSWORD,
            vendor_version=2,
            strength=3,
            method=8,
            tamper_hmac=tamper,
        )
        with open_archive(
            io.BytesIO(data), password=passwords, seekable_members=True, config=config
        ) as ar:
            member = ar.members()[0]
            if tamper:
                with pytest.raises((CorruptionError, EncryptionError)):
                    ar.read(member)
            else:
                assert ar.read(member) == payload
    # The accelerator did move the decrypt stage, so the HMAC above survived real
    # out-of-order reads rather than a straight pass.
    assert moving_seeks


@pytest.mark.parametrize("method", [0, 8], ids=["stored", "deflate"])
@requires("cryptography")
def test_aes_tampered_hmac_partial_read_then_close_is_quiet(method: int) -> None:
    """Partial read then close is not an HMAC verdict (ADR 0014).

    STORED used to drain and raise from ``close()``. Compressed members already
    skipped that check (S1-F1): the decompressor borrows the decrypt stream.
    Removing the drain makes both paths match CRC members.
    """
    # Incompressible and larger than one codec feed so DEFLATE cannot exhaust
    # the ciphertext (and therefore the HMAC) on a 16-byte read.
    payload = os.urandom(300 * 1024)
    data = _build_aes_zip(
        payload=payload,
        password=_PASSWORD,
        vendor_version=2,
        strength=3,
        method=method,
        tamper_hmac=True,
    )
    with (
        open_archive(io.BytesIO(data), password=_PASSWORD) as ar,
        ar.open(ar.members()[0]) as stream,
    ):
        assert len(stream.read(16)) == 16
        stream.close()  # must not raise CorruptionError


class _CloseCounter(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        super().close()


def _aes_decrypt_stream(source: io.BytesIO) -> WinZipAesDecryptStream:
    return WinZipAesDecryptStream(
        source,
        enc_key=b"\x00" * 16,
        auth_key=b"\x00" * 16,
        cipher_len=50,
    )


@requires("cryptography")
def test_aes_decrypt_stream_close_releases_source() -> None:
    """Partial read then close still owns the source; a second close is a no-op.

    Releasing ``_source`` is the only thing ``close()`` does.
    """
    src = _CloseCounter(b"\x00" * 60)
    stream = _aes_decrypt_stream(src)
    assert len(stream.read(16)) == 16
    stream.close()
    assert src.closed
    assert src.close_calls == 1
    assert stream.closed
    stream.close()
    assert src.close_calls == 1


@requires("cryptography")
def test_aes_decrypt_stream_close_marks_wrapper_closed_when_source_raises() -> None:
    """A teardown OSError from the source still marks the wrapper closed.

    ADR 0014: teardown errors propagate. ``super().close()`` must still run so a
    later ``close()`` does not retry the source.
    """

    class BoomSource(io.BytesIO):
        def close(self) -> None:
            super().close()
            raise OSError("teardown")

    stream = _aes_decrypt_stream(BoomSource(b"\x00" * 60))
    stream.read(16)
    with pytest.raises(OSError, match="teardown"):
        stream.close()
    assert stream.closed
    stream.close()  # no-op; must not re-raise


def _truncated_aes_parts() -> tuple[bytes, bytes, bytes, bytes, bytes]:
    salt = b"\x11" * 16
    enc_key, auth_key, _ = derive_winzip_aes_keys(_PASSWORD, salt=salt, key_len=32)
    ciphertext = aes_ctr_le_encrypt(enc_key, _PAYLOAD)
    mac = hmac.new(auth_key, ciphertext, hashlib.sha1).digest()[:10]
    return salt, enc_key, auth_key, ciphertext, mac


@requires("cryptography")
@pytest.mark.parametrize(
    ("cut", "match"),
    [("ciphertext", "ciphertext before HMAC"), ("mac", "Truncated WinZip AES HMAC")],
)
def test_aes_stream_short_source_raises_truncated(cut: str, match: str) -> None:
    """A source that ends before the declared ciphertext or HMAC is a truncation."""
    _, enc_key, auth_key, ciphertext, mac = _truncated_aes_parts()
    body = ciphertext[:400] if cut == "ciphertext" else ciphertext + mac[:4]
    stream = WinZipAesDecryptStream(
        io.BytesIO(body), enc_key=enc_key, auth_key=auth_key, cipher_len=len(ciphertext)
    )
    with pytest.raises(TruncatedError, match=match):
        stream.read(-1)


@requires("cryptography")
@pytest.mark.parametrize(
    ("keep", "match"), [(8, "salt"), (17, "password-verification value")]
)
def test_aes_member_short_envelope_raises_truncated(keep: int, match: str) -> None:
    """A payload cut inside the salt or the verifier is a truncation too."""
    salt, *_ = _truncated_aes_parts()
    raw = io.BytesIO((salt + b"\x00\x00")[:keep])
    with pytest.raises(TruncatedError, match=match):
        open_winzip_aes_member(
            raw,
            aes=WinZipAesInfo(vendor_version=2, strength=3, actual_method=0),
            password=_PASSWORD,
            compress_size=len(_PAYLOAD) + 28,
        )


@requires("cryptography")
def test_aes_member_impossible_declared_size_stays_corruption() -> None:
    """A declared size too small to hold the envelope is a bad header, not a short read."""
    with raises_corruption_not_truncation(match="too short") as exc:
        open_winzip_aes_member(
            io.BytesIO(b"\x00" * 64),
            aes=WinZipAesInfo(vendor_version=2, strength=3, actual_method=0),
            password=_PASSWORD,
            compress_size=10,
        )
    assert not isinstance(exc.value, TruncatedError)


@requires("cryptography")
def test_aes_multi_password_selects_winner() -> None:
    data = _build_aes_zip(
        payload=_PAYLOAD, password=_PASSWORD, vendor_version=2, strength=3, method=8
    )
    with open_archive(
        io.BytesIO(data), password=[b"nope", b"also-wrong", _PASSWORD]
    ) as ar:
        assert ar.read(ar.members()[0]) == _PAYLOAD


def _minimal_aes_zip_bytes(body: bytes | None = None) -> bytes:
    """A tiny method-99 ZIP with a valid 0x9901 extra (no cryptography needed to build).

    The ciphertext body is garbage — only used to exercise the cryptography-absent path,
    which fails before decryption. ``body`` replaces it; the declared sizes follow.
    """
    name = b"x.txt"
    # AE-2, strength 1 (128), actual method STORED
    aes_extra = struct.pack("<H2sBH", 2, b"AE", 1, 0)
    extra = struct.pack("<HH", 0x9901, len(aes_extra)) + aes_extra
    if body is None:
        # salt(8) + verify(2) + cipher(1) + hmac(10)
        body = b"\0" * (8 + 2 + 1 + 10)
    flags = 0x1
    local = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,
        51,
        flags,
        99,
        0,
        0,
        0,
        len(body),
        1,
        len(name),
        len(extra),
    )
    local += name + extra + body
    cd = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,
        51,
        51,
        flags,
        99,
        0,
        0,
        0,
        len(body),
        1,
        len(name),
        len(extra),
        0,
        0,
        0,
        0,
        0,
    )
    cd += name + extra
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd), len(local), 0)
    return local + cd + eocd


def test_aes_without_crypto_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _minimal_aes_zip_bytes()
    import archivey.internal.backends.zip_aes as zip_aes_module

    monkeypatch.setattr(zip_aes_module, "_crypto_available", lambda: False)
    with open_archive(io.BytesIO(data), password=_PASSWORD) as ar:
        (member,) = ar.members()
        assert member.is_encrypted  # detection still works
        with pytest.raises(PackageNotInstalledError, match="cryptography"):
            ar.read(member)


@pytest.mark.parametrize(
    "password", [_PASSWORD, [b"wrong", _PASSWORD]], ids=["single", "multi"]
)
def test_aes_header_too_short_is_corruption_without_crypto(
    monkeypatch: pytest.MonkeyPatch, password: bytes | list[bytes]
) -> None:
    """An impossible AES header is ``CorruptionError`` whether or not ``cryptography`` is installed.

    No library can read a member whose declared size cannot hold salt, verification
    value and HMAC, so the missing package is not the reason it fails (DR-5).
    """
    import archivey.internal.backends.zip_aes as zip_aes_module

    monkeypatch.setattr(zip_aes_module, "_crypto_available", lambda: False)
    data = _minimal_aes_zip_bytes(body=b"\0" * 5)
    with open_archive(io.BytesIO(data), password=password) as ar:
        (member,) = ar.members()
        with raises_corruption_not_truncation() as excinfo:
            ar.open(member)
    assert excinfo.value.member_name == "x.txt"


def test_parse_aes_extra_roundtrip() -> None:
    extra = struct.pack("<HH", 0x9901, 7) + struct.pack("<H2sBH", 2, b"AE", 3, 8)
    info = parse_winzip_aes_extra(extra)
    assert info is not None
    assert info.is_ae2
    assert info.key_bits == 256
    assert info.actual_method == 8
    assert parse_winzip_aes_extra(b"") is None


def test_iter_extra_fields_edge_shapes() -> None:
    def tlv(tag: int, data: bytes, size: int | None = None) -> bytes:
        return struct.pack("<HH", tag, len(data) if size is None else size) + data

    two = tlv(0x0001, b"ab") + tlv(0x7075, b"xyz")
    assert list(iter_extra_fields(two)) == [
        ExtraField(0x0001, b"ab", True),
        ExtraField(0x7075, b"xyz", True),
    ]
    # Over-declared last field: the bytes present, flagged incomplete.
    assert list(iter_extra_fields(tlv(0x0001, b"ab") + tlv(0x9901, b"AE", 7))) == [
        ExtraField(0x0001, b"ab", True),
        ExtraField(0x9901, b"AE", False),
    ]
    # A zero-size field is complete and does not stop the walk.
    assert list(iter_extra_fields(tlv(0x0017, b"") + tlv(0x0001, b"q"))) == [
        ExtraField(0x0017, b"", True),
        ExtraField(0x0001, b"q", True),
    ]
    # 1-3 stray trailing bytes cannot hold a header and are ignored.
    for stray in (b"\x01", b"\x01\x02", b"\x01\x02\x03"):
        assert list(iter_extra_fields(two + stray)) == list(iter_extra_fields(two))
    assert list(iter_extra_fields(b"")) == []


def test_extra_field_order_is_pinned() -> None:
    # split_extra_fields builds ExtraField positionally with tuple.__new__, which
    # cannot notice a reordered or added field.
    assert ExtraField._fields == ("tag", "data", "complete")


@pytest.mark.parametrize("seed", range(40))
def test_lazy_and_eager_extra_field_walks_agree(seed: int) -> None:
    # iter_extra_fields (lazy, for early-exit probes) and split_extra_fields (eager,
    # for the listing) are two loops that must read every blob the same way.
    rng = random.Random(seed)
    pieces = []
    for _ in range(rng.randrange(0, 6)):
        data = rng.randbytes(rng.randrange(0, 12))
        size = len(data) + rng.choice((0, 0, 0, 1, 5))  # sometimes over-declared
        pieces.append(struct.pack("<HH", rng.randrange(0x10000), size) + data)
    blob = b"".join(pieces) + rng.randbytes(rng.randrange(0, 4))
    for cut in range(len(blob) + 1):
        assert tuple(iter_extra_fields(blob[:cut])) == split_extra_fields(blob[:cut])


def test_aes_stream_guard_runs_before_the_cryptography_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A ``[core-only]`` install must reach the typed error, not ``ImportError``.

    The other test here patches ``_crypto_available`` while the real package is still
    importable, so it cannot see which of the two lines runs first. Making the import
    itself fail can: with the guard below the import, this raised ``ImportError``.
    """
    import sys

    import archivey.internal.backends.zip_aes as zip_aes_module

    monkeypatch.setattr(zip_aes_module, "_crypto_available", lambda: False)
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.ciphers", None)

    with pytest.raises(PackageNotInstalledError, match="cryptography"):
        WinZipAesDecryptStream(
            io.BytesIO(b""), enc_key=b"\0" * 32, auth_key=b"\0" * 32, cipher_len=0
        )


# The password ladder: several candidates are confirmed, not taken on pw_verify.

_COLLIDER = b"collides-on-pw-verify"


def _collide_pw_verify(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make ``_COLLIDER`` pass the 2-byte check while deriving its own (wrong) keys.

    A real collision takes ~65 000 PBKDF2 runs to find, so the test forges one: the
    reader's cheap check then admits a wrong password, as it does for 1 in 65 536.
    """
    from archivey.internal.backends import zip_aes

    original = zip_aes.derive_winzip_aes_keys

    def derive(password: bytes, *, salt: bytes, key_len: int) -> tuple[bytes, ...]:
        keys = original(password, salt=salt, key_len=key_len)
        if password != _COLLIDER:
            return keys
        right = original(_PASSWORD, salt=salt, key_len=key_len)
        return keys[0], keys[1], right[2]

    monkeypatch.setattr(zip_aes, "derive_winzip_aes_keys", derive)


@requires("cryptography")
@pytest.mark.parametrize("vendor_version", [1, 2], ids=["ae1", "ae2"])
@pytest.mark.parametrize("method", [0, 8], ids=["stored", "deflate"])
def test_aes_candidate_passing_pw_verify_does_not_shadow_the_right_one(
    monkeypatch: pytest.MonkeyPatch, vendor_version: int, method: int
) -> None:
    data = _build_aes_zip(
        payload=_PAYLOAD,
        password=_PASSWORD,
        vendor_version=vendor_version,
        strength=3,
        method=method,
    )
    _collide_pw_verify(monkeypatch)
    with open_archive(io.BytesIO(data), password=[_COLLIDER, _PASSWORD]) as ar:
        assert ar.read(ar.members()[0]) == _PAYLOAD


@requires("cryptography")
@pytest.mark.parametrize("method", [0, 8], ids=["stored", "deflate"])
def test_aes_only_colliding_candidates_report_damage(
    monkeypatch: pytest.MonkeyPatch, method: int
) -> None:
    """A wrong password past ``pw_verify`` reads as damage, as with one password.

    It passes the 16-bit check once in 65 536 tries, so a member every such candidate
    fails is reported as the likelier cause (S28-K4).
    """
    data = _build_aes_zip(
        payload=_PAYLOAD,
        password=_PASSWORD,
        vendor_version=2,
        strength=3,
        method=method,
    )
    _collide_pw_verify(monkeypatch)
    with (
        open_archive(io.BytesIO(data), password=[_COLLIDER, b"plain-wrong"]) as ar,
        raises_corruption_not_truncation(match="most likely damaged"),
    ):
        ar.read(ar.members()[0])


@requires("cryptography")
def test_aes_lone_colliding_password_fails_on_the_hmac(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With one password there is nothing to choose between: the HMAC at EOF decides."""
    data = _build_aes_zip(
        payload=_PAYLOAD, password=_PASSWORD, vendor_version=2, strength=3, method=0
    )
    _collide_pw_verify(monkeypatch)
    with (
        open_archive(io.BytesIO(data), password=_COLLIDER) as ar,
        raises_corruption_not_truncation(match="HMAC"),
    ):
        ar.read(ar.members()[0])


def _ctr_stream(payload: bytes, *, tamper_mac: bool = False) -> WinZipAesDecryptStream:
    """A decrypt stream over ``payload`` encrypted as WinZip AES-256, MAC appended."""
    enc_key, auth_key = os.urandom(32), os.urandom(32)
    cipher = aes_ctr_le_encrypt(enc_key, payload)
    mac = hmac.new(auth_key, cipher, hashlib.sha1).digest()[:10]
    if tamper_mac:
        mac = bytes([mac[0] ^ 1]) + mac[1:]
    return WinZipAesDecryptStream(
        io.BytesIO(cipher + mac),
        enc_key=enc_key,
        auth_key=auth_key,
        cipher_len=len(cipher),
    )


@requires("cryptography")
def test_aes_decrypt_stream_seeks_at_every_block_phase() -> None:
    # The counter for byte p is 1 + p // 16 and the stage discards p % 16 keystream
    # bytes; every phase of the first blocks, and backward after forward.
    payload = os.urandom(100)
    stream = _ctr_stream(payload)
    for target in [*range(50), 99, 100, 17, 0, 64, 3]:
        assert stream.seek(target) == target
        assert stream.tell() == target
        assert stream.read(7) == payload[target : target + 7]
        assert stream.tell() == min(target + 7, 100)
    assert stream.seek(-10, io.SEEK_END) == 90
    assert stream.read() == payload[90:]
    assert stream.seek(-5, io.SEEK_CUR) == 95
    assert stream.read() == payload[95:]


@pytest.mark.parametrize(
    "moves",
    [
        [(5, -1)],  # skip the start, read to the end
        [(0, 30), (60, 10), (20, 50), (90, -1)],  # scattered, overlapping reads
        [(0, 10), (50, -1)],  # a gap after a hashed prefix
        [(90, 10)],  # read(n) that ends exactly at the end
    ],
)
@requires("cryptography")
def test_aes_decrypt_stream_seeks_keep_the_hmac(moves: list[tuple[int, int]]) -> None:
    """The HMAC covers the ciphertext, so the read that reaches the end completes it
    over what seeks skipped. A tampered MAC raises and an intact one reads clean,
    whatever path the reads took."""
    payload = os.urandom(100)
    for tamper in (False, True):
        stream = _ctr_stream(payload, tamper_mac=tamper)
        *head, (last_at, last_n) = moves
        for at, n in head:
            stream.seek(at)
            assert stream.read(n) == payload[at : at + n]
        stream.seek(last_at)
        if tamper:
            with raises_corruption_not_truncation(match="HMAC"):
                stream.read(last_n)
        else:
            expected = payload[last_at:] if last_n < 0 else payload[last_at:][:last_n]
            assert stream.read(last_n) == expected


@pytest.mark.parametrize("tamper", ["none", "mac", "ciphertext"])
@requires("cryptography")
def test_aes_decrypt_stream_hmac_across_a_pull_that_straddles_the_frontier(
    tamper: str,
) -> None:
    """A pull that starts behind the hashed prefix and ends past it hashes only the
    part past it: no byte is hashed twice, and none is skipped.

    Over one pull (64 KiB) of ciphertext, so the first read leaves the prefix inside
    the member and the pull after the seek back straddles it.
    """
    enc_key, auth_key = os.urandom(32), os.urandom(32)
    payload = os.urandom(200 * 1024)
    cipher = bytearray(aes_ctr_le_encrypt(enc_key, payload))
    mac = hmac.new(auth_key, bytes(cipher), hashlib.sha1).digest()[:10]
    if tamper == "mac":
        mac = bytes([mac[0] ^ 1]) + mac[1:]
    elif tamper == "ciphertext":
        cipher[150_000] ^= 1  # past every byte the reads below decrypt
    stream = WinZipAesDecryptStream(
        io.BytesIO(bytes(cipher) + mac),
        enc_key=enc_key,
        auth_key=auth_key,
        cipher_len=len(cipher),
    )
    assert stream.read(70_000) == payload[:70_000]
    assert stream._hashed == 2 * 65536  # two pulls: the prefix ends mid-member
    stream.seek(1000)
    if tamper == "none":
        assert stream.read() == payload[1000:]
    else:
        with raises_corruption_not_truncation(match="HMAC"):
            stream.read()


@requires("cryptography")
def test_aes_decrypt_stream_reports_its_size() -> None:
    """The codec layer's accelerator threshold reads the stage's exact size."""
    payload = os.urandom(100)
    assert source_byte_size(_ctr_stream(payload)) == 100


@requires("cryptography")
def test_aes_decrypt_stream_catches_tampered_ciphertext_a_seek_skipped() -> None:
    """A byte the caller seeked over is still authenticated."""
    enc_key = b"\x07" * 32
    auth_key = b"\x09" * 20
    payload = os.urandom(100)
    cipher = bytearray(aes_ctr_le_encrypt(enc_key, payload))
    mac = hmac.new(auth_key, bytes(cipher), hashlib.sha1).digest()[:10]
    cipher[3] ^= 1  # inside the range the reads below never touch
    stream = WinZipAesDecryptStream(
        io.BytesIO(bytes(cipher) + mac),
        enc_key=enc_key,
        auth_key=auth_key,
        cipher_len=len(cipher),
    )
    stream.seek(50)
    with raises_corruption_not_truncation(match="HMAC"):
        stream.read()


@requires("cryptography")
def test_aes_decrypt_stream_partial_read_after_seek_has_no_verdict() -> None:
    payload = os.urandom(100)
    stream = _ctr_stream(payload, tamper_mac=True)
    stream.seek(40)
    assert stream.read(20) == payload[40:60]
    stream.close()


@requires("cryptography")
def test_aes_decrypt_stream_seek_to_current_position_keeps_the_hmac() -> None:
    payload = os.urandom(100)
    stream = _ctr_stream(payload, tamper_mac=True)
    assert stream.read(20) == payload[:20]
    stream.seek(20)
    with raises_corruption_not_truncation(match="HMAC"):
        stream.read()


@pytest.mark.parametrize("method", [0, 8], ids=["stored", "deflate"])
@requires("cryptography")
def test_aes_member_seeks(method: int) -> None:
    payload = os.urandom(5000) + _PAYLOAD
    data = _build_aes_zip(
        payload=payload,
        password=_PASSWORD,
        vendor_version=1,
        strength=3,
        method=method,
    )
    with (
        open_archive(io.BytesIO(data), password=_PASSWORD, seekable_members=True) as ar,
        ar.open(ar.members()[0]) as stream,
    ):
        assert stream.seekable()
        stream.seek(4099)
        assert stream.read(100) == payload[4099:4199]
        stream.seek(17)
        assert stream.read() == payload[17:]
        stream.seek(0)
        assert stream.read() == payload


@requires("cryptography")
def test_aes_stored_out_of_range_seeks_match_an_unencrypted_member() -> None:
    """A STORED member's seek reaches the decrypt stage directly, and lands where the
    same member unencrypted does: a relative underflow clamps to 0 and a past-end
    seek keeps its position."""
    payload = b"hello"
    encrypted = _build_aes_zip(
        payload=payload, password=_PASSWORD, vendor_version=2, strength=3, method=0
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("x.txt", payload)
    results = []
    for blob in (encrypted, buf.getvalue()):
        with (
            open_archive(
                io.BytesIO(blob), password=_PASSWORD, seekable_members=True
            ) as ar,
            ar.open(ar.members()[0]) as stream,
        ):
            out: list[object] = []
            for offset, whence in (
                (-10, io.SEEK_END),
                (-100, io.SEEK_CUR),
                (1000, io.SEEK_SET),
            ):
                out += [stream.seek(offset, whence), stream.tell(), stream.read(2)]
            results.append(out)
    assert results[0] == results[1] == [0, 0, b"he", 0, 0, b"he", 1000, 1000, b""]


@pytest.mark.parametrize("method", [0, 8], ids=["stored", "deflate"])
@requires("cryptography")
def test_aes_tampered_hmac_with_candidates_raises_corruption(method: int) -> None:
    """A candidate list reports a failing HMAC as damage too (S28-K4).

    Every candidate that reached the HMAC had passed the 16-bit ``pw_verify``, which a
    wrong password passes once in 65 536, so damage is the likely cause, as it is with
    one password.
    """
    data = _build_aes_zip(
        payload=_PAYLOAD,
        password=_PASSWORD,
        vendor_version=2,
        strength=3,
        method=method,
        tamper_hmac=True,
    )
    with (
        open_archive(io.BytesIO(data), password=[b"nope", _PASSWORD]) as ar,
        raises_corruption_not_truncation(match="most likely damaged"),
    ):
        ar.read(ar.members()[0])


@pytest.mark.parametrize(
    "passwords", [_PASSWORD, [b"nope", _PASSWORD]], ids=["single", "candidates"]
)
@requires("cryptography")
def test_aes_short_payload_is_truncated_on_both_password_paths(
    passwords: bytes | list[bytes],
) -> None:
    """A member declaring more than it stores is ``TruncatedError`` either way.

    The candidate path used to turn it into ``CorruptionError``, so a caller catching
    ``TruncatedError`` saw it under one password and missed it under a list.
    """
    data = bytearray(
        _build_aes_zip(
            payload=b"hello world",
            password=_PASSWORD,
            vendor_version=2,
            strength=3,
            method=0,
            name=b"a.bin",
        )
    )
    for signature, size_at in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        struct.pack_into("<I", data, data.index(signature) + size_at, 100)
    with (
        open_archive(io.BytesIO(bytes(data)), password=passwords) as ar,
        pytest.raises(TruncatedError),
    ):
        ar.read(ar.members()[0])


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
@pytest.mark.parametrize("collider_first", [True, False], ids=["collider", "right"])
@requires("cryptography")
def test_aes_short_payload_is_truncated_whichever_candidate_fails_first(
    method: int, collider_first: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A short payload is the member's, so the verdict does not depend on key order.

    A wrong password that collides on ``pw_verify`` fails differently from the right
    one; taking the first failure made the type follow the list order (S28-K16).
    """
    data = bytearray(
        _build_aes_zip(
            payload=b"hello world" * 40,
            password=_PASSWORD,
            vendor_version=2,
            strength=3,
            method=method,
            name=b"a.bin",
        )
    )
    for signature, size_at in ((b"PK\x03\x04", 22), (b"PK\x01\x02", 24)):
        struct.pack_into("<I", data, data.index(signature) + size_at, 100_000)
    _collide_pw_verify(monkeypatch)
    passwords = [_COLLIDER, _PASSWORD] if collider_first else [_PASSWORD, _COLLIDER]
    with (
        open_archive(io.BytesIO(bytes(data)), password=passwords) as ar,
        pytest.raises(TruncatedError),
    ):
        ar.read(ar.members()[0])


@requires("cryptography")
def test_method_99_without_encryption_flag_lists_as_encrypted() -> None:
    """A method-99 member is encrypted whatever general-purpose bit 0 says.

    Crafted: no producer writes method 99 with bit 0 clear (DR-24 allows a crafted
    fixture for that). Opening already treats method 99 as encrypted and asks for
    a password, so the listing must say so too.
    """
    blob = bytearray(build_aes_zip([(b"x.txt", _PAYLOAD)], password=_PASSWORD))
    struct.pack_into("<H", blob, 6, 0)  # local file header flags
    cd_at = blob.find(b"PK\x01\x02")
    struct.pack_into("<H", blob, cd_at + 8, 0)  # central directory flags
    with open_archive(io.BytesIO(bytes(blob))) as ar:
        member = ar.members()[0]
        assert member.is_encrypted
        with pytest.raises(EncryptionError):
            ar.read(member)
    with open_archive(io.BytesIO(bytes(blob)), password=_PASSWORD) as ar:
        assert ar.read(ar.members()[0]) == _PAYLOAD
    # Without a 0x9901 extra no password is asked for, but the data is still
    # encrypted, so the listing still says so.
    no_extra = bytes(blob).replace(
        struct.pack("<H", 0x9901) + b"\x07\x00", b"\xfe\xca\x07\x00"
    )
    assert no_extra.count(b"\xfe\xca\x07\x00") == 2  # local and central headers
    with open_archive(io.BytesIO(no_extra), password=_PASSWORD) as ar:
        member = ar.members()[0]
        assert member.is_encrypted
        with pytest.raises(UnsupportedFeatureError, match="0x9901"):
            ar.open(member)


def _forward_envelope() -> tuple[bytes, bytes, bytes, bytes]:
    """Keys and an AE ciphertext with its code, for :class:`WinZipAesForwardStream`."""
    enc_key, auth_key, _ = derive_winzip_aes_keys(_PASSWORD, salt=bytes(16), key_len=32)
    cipher = aes_ctr_le_encrypt(enc_key, _PAYLOAD)
    mac = hmac.new(auth_key, cipher, hashlib.sha1).digest()[:10]
    return enc_key, auth_key, cipher, mac


@requires("cryptography")
@pytest.mark.parametrize("pulled", [0, 4, 10, 30])
@pytest.mark.parametrize("tamper", [False, True])
def test_forward_stream_authenticates_once_told_where_the_data_ends(
    pulled: int, tamper: bool
) -> None:
    """A codec member's stage reads past the code into what follows, or stops short
    of it; the walk's ``passed_over`` holds what it did not read."""
    enc_key, auth_key, cipher, mac = _forward_envelope()
    if tamper:
        mac = bytes([mac[0] ^ 1]) + mac[1:]
    rest = mac + b"PK\x07\x08 and what follows"
    read, passed_over = rest[:pulled], rest[pulled:10] if pulled < 10 else b""
    stage = WinZipAesForwardStream(
        io.BytesIO(cipher + read),
        enc_key=enc_key,
        auth_key=auth_key,
        header_len=18,
        hold_back=64,
    )
    assert stage.read(len(_PAYLOAD)) == _PAYLOAD
    stage.read(1 << 10)  # on into the code and past it, as a codec's layers read ahead
    with pytest.raises(ValueError, match="read it in pieces"):
        stage.read()
    with pytest.raises(ValueError, match="read it in pieces"):
        stage.readall()
    data_len = 18 + len(cipher) + 10
    if tamper:
        with pytest.raises(CorruptionError, match="HMAC mismatch"):
            stage.authenticate_end(data_len, passed_over)
    else:
        stage.authenticate_end(data_len, passed_over)
    with pytest.raises(CorruptionError, match=r"too short .*\(27 < 28\)"):
        stage.authenticate_end(27, b"")


@requires("cryptography")
@pytest.mark.parametrize("tamper", [False, True])
def test_forward_stream_ending_with_its_data_holds_back_the_code(tamper: bool) -> None:
    enc_key, auth_key, cipher, mac = _forward_envelope()
    if tamper:
        mac = bytes([mac[0] ^ 1]) + mac[1:]
    stage = WinZipAesForwardStream(
        io.BytesIO(cipher[10:] + mac),
        enc_key=enc_key,
        auth_key=auth_key,
        header_len=18,
        hold_back=None,
        read_ahead=cipher[:10],
    )
    if tamper:
        with pytest.raises(CorruptionError, match="HMAC mismatch"):
            stage.read()
    else:
        assert stage.read() == _PAYLOAD


@pytest.mark.parametrize(
    ("hold_back", "data", "refusal"),
    [
        # Whole and too short: no library could read it, so the gate comes after.
        pytest.param(None, b"\x01" * 20, CorruptionError, id="too-short"),
        # Cut: the gate comes first, as for a sized member.
        pytest.param(64, b"\x01" * 5, PackageNotInstalledError, id="cut"),
    ],
)
def test_forward_open_checks_in_the_sized_open_order(
    monkeypatch: pytest.MonkeyPatch,
    hold_back: int | None,
    data: bytes,
    refusal: type[Exception],
) -> None:
    monkeypatch.setattr(zip_aes, "_crypto_available", lambda: False)
    with pytest.raises(refusal):
        open_winzip_aes_forward(
            io.BytesIO(data),
            aes=WinZipAesInfo(2, 3, 8),
            password=_PASSWORD,
            hold_back=hold_back,
        )


@requires("cryptography")
@pytest.mark.parametrize("forward", [False, True], ids=["sized", "forward"])
def test_aes_hmac_mismatch_keeps_withholding_the_last_chunk(forward: bool) -> None:
    """A read after the mismatch raises again; it never hands out the chunk the
    failed read withheld, or a clean end."""
    payload = os.urandom(100_000)
    enc_key, auth_key = os.urandom(32), os.urandom(32)
    cipher = aes_ctr_le_encrypt(enc_key, payload)
    mac = bytes(10)
    stage: WinZipAesDecryptStream | WinZipAesForwardStream
    if forward:
        stage = WinZipAesForwardStream(
            io.BytesIO(cipher + mac),
            enc_key=enc_key,
            auth_key=auth_key,
            header_len=18,
            hold_back=None,
        )
    else:
        stage = WinZipAesDecryptStream(
            io.BytesIO(cipher + mac),
            enc_key=enc_key,
            auth_key=auth_key,
            cipher_len=len(cipher),
        )
    out = b""
    with pytest.raises(CorruptionError, match="HMAC mismatch"):
        while chunk := stage.read(1 << 16):
            out += chunk
    assert payload.startswith(out)
    assert len(out) < len(payload)
    for _ in range(2):
        with pytest.raises(CorruptionError, match="HMAC mismatch"):
            stage.read(1 << 16)
    # A zero-length read carries no verdict, as on any ``io`` stream.
    assert stage.read(0) == b""


def test_aes_record_differences_compares_every_record_field() -> None:
    """``aes_record_differences`` names each field it compares. A field added to
    ``WinZipAesInfo`` must be compared there too, or its difference comes out only as
    the generic fallback item."""
    compared = {"vendor_version", "strength", "actual_method"}
    assert {field.name for field in dataclasses.fields(WinZipAesInfo)} == compared
    local, central = WinZipAesInfo(1, 1, 0), WinZipAesInfo(2, 3, 8)
    differ = zip_aes.aes_record_differences(local, central)
    assert differ == [
        "AE-1 against AE-2",
        "AES key strength 1 against 3",
        "AES compression method 0 against 8",
    ]
    assert zip_aes.local_first(differ) == ", local first"
    assert zip_aes.aes_record_differences(local, local) == []
    missing = zip_aes.aes_record_differences(None, central)
    assert missing == ["the local header holds no valid WinZip AES record"]
    assert zip_aes.local_first(missing) == ""
