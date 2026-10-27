"""Shared WinZip AES ZIP builders for tests and the benchmark harness.

Hand-rolls AE-1 / AE-2 method-99 members (stdlib ``zipfile`` cannot write AES).
Kept next to :mod:`tests.zipcrypto` as fixture scaffolding — not a public writer.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
import zlib
from collections.abc import Callable, Sequence

from archivey.internal.backends.zip_aes import WinZipAesInfo, derive_winzip_aes_keys


def aes_ctr_le_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """WinZip AES counter mode: little-endian block counter starting at 1."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray(len(plaintext))
    keystream = b""
    pos = 0
    counter = 1
    for i, byte in enumerate(plaintext):
        if pos >= len(keystream):
            keystream = encryptor.update(counter.to_bytes(16, "little"))
            pos = 0
            counter += 1
        out[i] = byte ^ keystream[pos]
        pos += 1
    return bytes(out)


def build_aes_zip(
    members: Sequence[tuple[bytes, bytes]],
    *,
    password: bytes,
    vendor_version: int = 2,
    strength: int = 3,
    method: int = 8,
    tamper_hmac: bool = False,
    unix_mode: int | None = None,
    compressed_tail: bytes = b"",
    encode: Callable[[bytes], bytes] | None = None,
) -> bytes:
    """Build a WinZip AES ZIP from ``(name, payload)`` members.

    ``tamper_hmac`` flips a byte in the first member's AES HMAC (for corruption
    tests). ``unix_mode`` records every member as written on Unix with that mode
    (``0o120777`` makes them symlinks). ``compressed_tail`` is appended to each
    member's compressed data before encryption, inside the member. AE-2
    (``vendor_version=2``) stores CRC 0 in the headers; AE-1 stores the plaintext CRC.
    ``encode`` compresses each payload for a ``method`` this builder cannot write.
    """
    if not members:
        raise ValueError("build_aes_zip requires at least one member")
    if encode is None and method not in (0, 8):
        raise ValueError(f"unsupported underlying method {method}")

    aes = WinZipAesInfo(vendor_version, strength, method)
    locals_blob = bytearray()
    central = bytearray()

    for index, (name, payload) in enumerate(members):
        if encode is not None:
            compressed = encode(payload)
        elif method == 0:
            compressed = payload
        else:
            compressed = zlib.compress(payload)[2:-4]  # raw deflate
        compressed += compressed_tail
        # A fixed salt per member: with a random one, a wrong password passes the
        # 2-byte verifier about once in 65,536 builds and the test that expects
        # EncryptionError sees the decoder's CorruptionError instead.
        salt = hashlib.sha256(b"archivey-test-salt:%d:" % index + name).digest()[
            : aes.salt_len
        ]
        enc_key, auth_key, pw_verify = derive_winzip_aes_keys(
            password, salt=salt, key_len=aes.key_len
        )
        ciphertext = aes_ctr_le_encrypt(enc_key, compressed)
        mac = bytearray(hmac.new(auth_key, ciphertext, hashlib.sha1).digest()[:10])
        if tamper_hmac and index == 0:
            mac[0] ^= 0xFF
        body = salt + pw_verify + ciphertext + bytes(mac)
        crc = 0 if vendor_version == 2 else (zlib.crc32(payload) & 0xFFFFFFFF)
        aes_extra = struct.pack("<H2sBH", vendor_version, b"AE", strength, method)
        extra = struct.pack("<HH", 0x9901, len(aes_extra)) + aes_extra
        flags = 0x1  # encrypted
        offset = len(locals_blob)
        local = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            51,  # version needed (AES)
            flags,
            99,
            0,
            0,
            crc,
            len(body),
            len(payload),
            len(name),
            len(extra),
        )
        locals_blob.extend(local)
        locals_blob.extend(name)
        locals_blob.extend(extra)
        locals_blob.extend(body)
        cd = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            51 if unix_mode is None else 0x0300 | 51,  # made by: 3 = Unix
            51,
            flags,
            99,
            0,
            0,
            crc,
            len(body),
            len(payload),
            len(name),
            len(extra),
            0,
            0,
            0,
            0 if unix_mode is None else unix_mode << 16,
            offset,
        )
        central.extend(cd)
        central.extend(name)
        central.extend(extra)

    n = len(members)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        n,
        n,
        len(central),
        len(locals_blob),
        0,
    )
    return bytes(locals_blob) + bytes(central) + eocd
