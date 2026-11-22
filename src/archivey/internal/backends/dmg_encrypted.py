"""Encrypted DMG images: the ``encrcdsa`` (v2) header, the password check, and the
decrypted view the UDIF reader runs on (design §6B of
``openspec/changes/dmg-reader``; the layout in ``dev-docs/formats/dmg.md`` §2.1.1).

``hdiutil -encryption`` encrypts a whole UDIF image (data fork, property list,
``koly`` block) and puts this header in front. The header holds one or more key
entries; a password entry wraps the image's AES key and HMAC-SHA1 key with a key
derived from the password by PBKDF2-HMAC-SHA1. The image is cut in blocks of the
header's block size; block ``n`` is AES-CBC with the IV
``HMAC-SHA1(hmac_key, n as a big-endian u32)[:16]``.

Every length in the header is checked before the bytes it names are read, and only
the ``koly`` block is decrypted to check a password: the rest is decrypted a block at a
time as the UDIF reader asks for it.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import struct
import threading
from collections import OrderedDict
from typing import BinaryIO, NamedTuple

from archivey.exceptions import (
    CorruptionError,
    ResourceLimitError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import PasswordConfirmVerdict, ReaderContext, ReaderSource
from archivey.internal.backends.udif import DiskView, parse_koly
from archivey.internal.overrides import override
from archivey.internal.streams.crypto import (
    AesParams,
    CryptoBackend,
    get_crypto_backend,
    note_crypto_use,
)

SIGNATURE = b"encrcdsa"

# The fixed header: signature, version, IV size, mode, algorithm, key bits, PRNG
# algorithm, HMAC key bits, UUID, block size, data size, data offset, key-entry count.
_HEADER = struct.Struct(">8s7I16sIQQI")
# A key entry: type, offset of its blob in the file, blob size.
_ENTRY = struct.Struct(">IQQ")
# A password key blob up to the wrapped key: KDF algorithm, KDF PRNG algorithm,
# iterations, salt length, salt (32-byte field), IV length, IV (32-byte field), wrapping
# key bits, wrapping algorithm, padding, mode, wrapped-key length.
_BLOB = struct.Struct(">4I32sI32s5I")

_VERSION = 2
# Apple's CSSM algorithm ids: ``CSSM_ALGID_AES`` (vendor-defined + 1) and
# ``CSSM_ALGID_3DES_3KEY_EDE``.
_ALG_AES = 0x80000001
_ALG_3DES = 17
_KDF_PBKDF2 = 103
_PADDING_PKCS7 = 7
_MODE_CBC = 6
_ENTRY_PASSWORD = 1
_HMAC_KEY_SIZE = 20
# Every image macOS 26 writes ends its unwrapped key with this mark and a zero byte.
_KEY_MARK = b"CKIE\0"
# The block sizes seen: 512 on every fixture (macOS 26), 4096 in the older images
# vfdecrypt and dmg2img describe.
_BLOCK_SIZES = (512, 4096)
# Caps from design §6B.4: the fixtures hold one entry of 616 bytes.
_MAX_ENTRIES = 16
_MAX_ENTRY_SIZE = 4096
_CACHE_BLOCKS = 16


class _PasswordEntry(NamedTuple):
    at: int  # the blob's file offset, for messages
    iterations: int
    salt: bytes
    iv: bytes
    algorithm: int  # _ALG_AES or _ALG_3DES
    key_size: int  # the wrapping key, in bytes
    wrapped: bytes


class EncryptedHeader(NamedTuple):
    key_size: int  # the image's AES key, in bytes
    block_size: int
    data_size: int  # the decrypted image's length
    data_offset: int
    entries: tuple[_PasswordEntry, ...]


class ImageKeys(NamedTuple):
    aes_key: bytes
    hmac_key: bytes
    # Whether the decrypted image ends with a ``koly`` block. A password confirmed by
    # the key mark alone unlocks an image that does not: a read-write (UDRW) one.
    has_koly: bool


def is_encrypted(source: ReaderSource) -> bool:
    return source.read_at(0, len(SIGNATURE)) == SIGNATURE


def read_header(source: ReaderSource) -> EncryptedHeader:
    """The ``encrcdsa`` header of ``source``, every length and offset checked."""
    raw = source.read_exact(0, _HEADER.size)
    (
        _,
        version,
        _iv_size,
        _mode,
        algorithm,
        key_bits,
        _prng,
        hmac_bits,
        _uuid,
        block_size,
        data_size,
        data_offset,
        count,
    ) = _HEADER.unpack(raw)
    if version != _VERSION:
        raise UnsupportedFeatureError(
            f"encrypted DMG images of header version {version} are not supported "
            f"(only version {_VERSION})"
        )
    if algorithm != _ALG_AES or key_bits not in (128, 192, 256):
        raise UnsupportedFeatureError(
            f"the encrypted DMG image uses cipher {algorithm:#x} with a {key_bits}-bit "
            "key; only AES is supported"
        )
    if hmac_bits != _HMAC_KEY_SIZE * 8:
        raise UnsupportedFeatureError(
            f"the encrypted DMG image declares a {hmac_bits}-bit HMAC key; only "
            f"{_HMAC_KEY_SIZE * 8} bits is supported"
        )
    if block_size not in _BLOCK_SIZES:
        raise UnsupportedFeatureError(
            f"the encrypted DMG image uses {block_size}-byte blocks; only "
            f"{' and '.join(map(str, _BLOCK_SIZES))} are supported"
        )
    if count == 0:
        raise CorruptionError("the encrypted DMG header declares no key entries")
    if count > _MAX_ENTRIES:
        raise ResourceLimitError(
            f"the encrypted DMG header declares {count} key entries; archivey reads "
            f"at most {_MAX_ENTRIES}"
        )
    table_end = _HEADER.size + count * _ENTRY.size
    if data_offset < table_end:
        raise CorruptionError(
            f"the encrypted DMG header puts the encrypted data at byte {data_offset}, "
            f"inside its own key table (which ends at byte {table_end})"
        )
    blocks = -(-data_size // block_size)
    if data_size == 0 or blocks > 1 << 32:
        raise CorruptionError(
            f"the encrypted DMG header declares {data_size} bytes of encrypted data"
        )
    end = data_offset + blocks * block_size
    size = _file_size(source)
    if size < end:
        raise TruncatedError(
            f"the encrypted DMG image ends at byte {size}, before the end of its "
            f"encrypted data at byte {end}"
        )
    table = source.read_exact(_HEADER.size, count * _ENTRY.size)
    entries: list[_PasswordEntry] = []
    for index in range(count):
        kind, offset, length = _ENTRY.unpack_from(table, index * _ENTRY.size)
        if length > _MAX_ENTRY_SIZE:
            raise ResourceLimitError(
                f"key entry {index + 1} of the encrypted DMG header is {length} "
                f"bytes; archivey reads at most {_MAX_ENTRY_SIZE}"
            )
        if offset < table_end or offset + length > data_offset:
            raise CorruptionError(
                f"key entry {index + 1} of the encrypted DMG header lies at bytes "
                f"{offset} to {offset + length}, outside the header (bytes {table_end} "
                f"to {data_offset})"
            )
        if kind != _ENTRY_PASSWORD:
            continue
        entries.append(_password_entry(source, offset, length))
    if not entries:
        raise UnsupportedFeatureError(
            "the encrypted DMG image is locked with a certificate or keychain key, "
            "not a password, which archivey does not read"
        )
    return EncryptedHeader(
        key_bits // 8, block_size, data_size, data_offset, tuple(entries)
    )


def _file_size(source: ReaderSource) -> int:
    size = source.size
    if size is None:
        with source.view(0) as whole:
            size = whole.seek(0, io.SEEK_END)
    return size


def _password_entry(source: ReaderSource, at: int, length: int) -> _PasswordEntry:
    if length < _BLOB.size:
        raise CorruptionError(
            f"the password key entry at byte {at} of the encrypted DMG header is "
            f"{length} bytes, shorter than its {_BLOB.size}-byte fields"
        )
    (
        kdf,
        _prng,
        iterations,
        salt_size,
        salt,
        iv_size,
        iv,
        key_bits,
        algorithm,
        padding,
        mode,
        wrapped_size,
    ) = _BLOB.unpack(source.read_exact(at, _BLOB.size))
    if kdf != _KDF_PBKDF2:
        raise UnsupportedFeatureError(
            f"the encrypted DMG image derives its key with algorithm {kdf}; only "
            "PBKDF2 is supported"
        )
    if iterations == 0:
        raise CorruptionError(
            f"the password key entry at byte {at} of the encrypted DMG header "
            "declares 0 PBKDF2 iterations"
        )
    if algorithm == _ALG_AES and key_bits in (128, 192, 256):
        block = 16
    elif algorithm == _ALG_3DES and key_bits == 192:
        block = 8
    else:
        raise UnsupportedFeatureError(
            f"the encrypted DMG image wraps its key with cipher {algorithm:#x} and a "
            f"{key_bits}-bit key; only AES and 3DES are supported"
        )
    if padding != _PADDING_PKCS7 or mode != _MODE_CBC:
        raise UnsupportedFeatureError(
            f"the encrypted DMG image wraps its key in mode {mode} with padding "
            f"{padding}; only CBC with PKCS#7 padding is supported"
        )
    # The IV field is 32 bytes. macOS 26 states an IV size of 8 for its AES wrap,
    # yet decrypts with the field's first 16 bytes (the 8 it states, then zeros):
    # each cipher takes its block size from the field.
    if salt_size > len(salt) or not 0 < iv_size <= block:
        raise CorruptionError(
            f"the password key entry at byte {at} of the encrypted DMG header "
            f"declares a {salt_size}-byte salt and a {iv_size}-byte IV (at most "
            f"{len(salt)}, and {block})"
        )
    if wrapped_size == 0 or wrapped_size % block or _BLOB.size + wrapped_size > length:
        raise CorruptionError(
            f"the password key entry at byte {at} of the encrypted DMG header "
            f"declares a {wrapped_size}-byte wrapped key"
        )
    wrapped = source.read_exact(at + _BLOB.size, wrapped_size)
    return _PasswordEntry(
        at,
        iterations,
        salt[:salt_size],
        iv[:block],
        algorithm,
        key_bits // 8,
        wrapped,
    )


class Unlocker:
    """The password check for one encrypted image (``NeedsPassword.check``)."""

    def __init__(
        self, source: ReaderSource, header: EncryptedHeader, context: ReaderContext
    ) -> None:
        self._source = source
        self._header = header
        self._context = context
        self.backend = get_crypto_backend(context.config.formats._libraries_off)
        note_crypto_use(context._usage)
        # The ciphertext of the blocks that hold the last 512 bytes: the ``koly``.
        size = header.data_size
        first = max(0, size - 512) // header.block_size
        last = (size - 1) // header.block_size
        self._tail_first = first
        self._tail = source.read_exact(
            header.data_offset + first * header.block_size,
            (last - first + 1) * header.block_size,
        )

    def check(self, password: bytes) -> tuple[ImageKeys | None, PasswordConfirmVerdict]:
        for entry in self._header.entries:
            keys = self._unwrap(entry, password)
            if keys is not None:
                return keys, PasswordConfirmVerdict.CONFIRMED
        return None, PasswordConfirmVerdict.REJECTED

    def _unwrap(self, entry: _PasswordEntry, password: bytes) -> ImageKeys | None:
        self._context.charge_key_derivation(entry.iterations)
        derived = hashlib.pbkdf2_hmac(
            "sha1", password, entry.salt, entry.iterations, entry.key_size
        )
        if entry.algorithm == _ALG_AES:
            stage = self.backend.aes_cbc_decrypt_stage(AesParams(derived, entry.iv))
            plain = stage.update(entry.wrapped) + stage.finalize()
        else:
            plain = self.backend.triple_des_cbc_decrypt(
                derived, entry.iv, entry.wrapped
            )
        pad = plain[-1]
        block = len(entry.iv)
        if not 0 < pad <= block or plain[-pad:] != bytes([pad]) * pad:
            return None
        plain = plain[:-pad]
        size = self._header.key_size
        if len(plain) < size + _HMAC_KEY_SIZE:
            return None
        aes_key = plain[:size]
        hmac_key = plain[size : size + _HMAC_KEY_SIZE]
        # A wrong password passes the padding check about once in 256 tries; the
        # ``koly`` block at the image's end, or the key mark, settles it.
        tail = self._decrypt(aes_key, hmac_key, self._tail_first, self._tail)
        koly_at = (
            self._header.data_size - 512 - self._tail_first * self._header.block_size
        )
        koly = tail[koly_at : koly_at + 512] if koly_at >= 0 else b""
        if parse_koly(koly, 0) is not None:
            return ImageKeys(aes_key, hmac_key, True)
        if plain[size + _HMAC_KEY_SIZE :] == _KEY_MARK:
            return ImageKeys(aes_key, hmac_key, False)
        return None

    def _decrypt(
        self, aes_key: bytes, hmac_key: bytes, first: int, data: bytes
    ) -> bytes:
        return decrypt_blocks(
            self.backend, aes_key, hmac_key, self._header.block_size, first, data
        )


def decrypt_blocks(
    backend: CryptoBackend,
    aes_key: bytes,
    hmac_key: bytes,
    block_size: int,
    first: int,
    data: bytes,
) -> bytes:
    """Decrypt ``data``, whole blocks of the image from block ``first``.

    One CBC pass over all of ``data``, from block ``first``'s IV, then a fix to the
    first 16 bytes of each later block: the pass XORed them with the previous block's
    last ciphertext bytes, where the image uses that block's own IV. One cipher call
    instead of one per block, which is most of the cost at 512-byte blocks.
    """
    count = len(data) // block_size
    if count == 0:
        return b""
    hmac_base = hmac.new(hmac_key, digestmod=hashlib.sha1)

    def iv_of(number: int) -> bytes:
        mac = hmac_base.copy()
        mac.update(number.to_bytes(4, "big"))
        return mac.digest()[:16]

    stage = backend.aes_cbc_decrypt_stage(AesParams(aes_key, iv_of(first)))
    out = bytearray(stage.update(data[: count * block_size]))
    for index in range(1, count):
        at = index * block_size
        wrong = int.from_bytes(data[at - 16 : at], "big")
        right = int.from_bytes(iv_of(first + index), "big")
        head = int.from_bytes(out[at : at + 16], "big") ^ wrong ^ right
        out[at : at + 16] = head.to_bytes(16, "big")
    return bytes(out)


class EncryptedDmgSource(ReaderSource):
    """The decrypted image, as a :class:`~archivey.formats.ReaderSource` the UDIF
    reader opens as it would the file. Offsets are the decrypted image's."""

    def __init__(
        self,
        source: ReaderSource,
        header: EncryptedHeader,
        keys: ImageKeys,
        backend: CryptoBackend,
    ) -> None:
        self._encrypted = source
        self._header = header
        self._keys = keys
        self._backend = backend
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        self._lock = threading.Lock()
        length = header.data_size

        def read_at(offset: int, n: int) -> bytes:
            if offset >= length or n <= 0:
                return b""
            return self._read(offset, min(n, length - offset))

        def view(offset: int, n: int | None) -> BinaryIO:
            span = length - offset if n is None else min(n, length - offset)
            raw = DiskView(read_at, offset, max(0, span))
            return io.BufferedReader(raw, buffer_size=64 << 10)

        super().__init__(view, length, None, read_at)
        self._origin = source._origin

    def _read(self, offset: int, n: int) -> bytes:
        size = self._header.block_size
        first = offset // size
        last = (offset + n - 1) // size
        out = bytearray()
        number = first
        while number <= last:
            cached = self._cached(number)
            if cached is not None:
                out += cached
                number += 1
                continue
            # The blocks up to the next cached one, or the last, in one file read.
            end = number
            while end < last and self._cached(end + 1) is None:
                end += 1
            plain = self._decrypt(number, end)
            out += plain
            self._keep(number, plain[:size])
            self._keep(end, plain[-size:])
            number = end + 1
        skip = offset - first * size
        return bytes(out[skip : skip + n])

    def _decrypt(self, first: int, last: int) -> bytes:
        size = self._header.block_size
        data = self._encrypted.read_exact(
            self._header.data_offset + first * size, (last - first + 1) * size
        )
        keys = self._keys
        return decrypt_blocks(
            self._backend, keys.aes_key, keys.hmac_key, size, first, data
        )

    def _cached(self, number: int) -> bytes | None:
        with self._lock:
            block = self._cache.get(number)
            if block is not None:
                self._cache.move_to_end(number)
            return block

    def _keep(self, number: int, block: bytes) -> None:
        with self._lock:
            self._cache[number] = block
            self._cache.move_to_end(number)
            while len(self._cache) > _CACHE_BLOCKS:
                self._cache.popitem(last=False)

    @override
    def read_exact(self, offset: int, n: int) -> bytes:
        data = self.read_at(offset, n)
        if len(data) < n:
            raise TruncatedError(
                f"the decrypted DMG image ends {len(data)} bytes into the {n} bytes "
                f"at its offset {offset}"
            )
        return data


__all__ = [
    "SIGNATURE",
    "EncryptedDmgSource",
    "EncryptedHeader",
    "ImageKeys",
    "Unlocker",
    "is_encrypted",
    "read_header",
]
