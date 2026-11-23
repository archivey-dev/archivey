"""Traditional ZipCrypto (PKWARE) stream cipher.

The decrypt stage of the ZIP member pipeline (:class:`ZipCryptoDecryptStream`, ahead of
the shared codec layer) and multi-candidate password confirmation for STORED members
(parallel CRC over raw ciphertext). Independent of :mod:`zipfile`'s private
``_ZipDecrypter``.

APPNOTE.txt §6.1: a 96-bit key state seeded from the password, a 12-byte
encryption header whose final plaintext byte is the verification value, then
payload bytes, each XORed with a keystream byte derived from the evolving state.
"""

from __future__ import annotations

import io
import zlib
from collections.abc import Sequence
from typing import BinaryIO

from archivey.internal import kernels
from archivey.internal.excluded_libraries import NO_EXCLUSIONS
from archivey.internal.kernels import ZipCryptoDecryptor
from archivey.internal.overrides import override
from archivey.internal.streams.streamtools import (
    ReadOnlyIOStream,
    read_exact,
    resolve_seek,
)
from archivey.types import OptionalLibrary

#: Length of the encryption header in front of every ZipCrypto member's data.
ZIPCRYPTO_HEADER_LEN = 12


def new_keys(
    password: bytes, excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS
) -> ZipCryptoDecryptor:
    """The key state for ``password``, as ``excluded`` allows
    (:func:`archivey.internal.kernels.zipcrypto`)."""
    return kernels.zipcrypto(excluded).Decryptor(password)


def keys_after_header(
    password: bytes,
    header_ciphertext: bytes,
    excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS,
) -> tuple[ZipCryptoDecryptor, int]:
    """Decrypt the 12-byte header; return the state after it and its last plaintext byte.

    The last byte is the check byte a correct password reproduces.
    """
    keys = new_keys(password, excluded)
    plain = keys.decrypt(header_ciphertext[:ZIPCRYPTO_HEADER_LEN])
    return keys, plain[-1]


def password_matches_check_byte(
    password: bytes,
    header_ciphertext: bytes,
    check_byte: int,
    excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS,
) -> bool:
    """Whether ``password`` satisfies ZipCrypto's 1-byte header check.

    ``header_ciphertext`` must be the first 12 encrypted bytes of the member.
    """
    if len(header_ciphertext) < ZIPCRYPTO_HEADER_LEN:
        return False
    _, plain_last = keys_after_header(password, header_ciphertext, excluded)
    return plain_last == check_byte


def parallel_plaintext_crc32(
    passwords: Sequence[bytes],
    header_ciphertext: bytes,
    body: BinaryIO,
    *,
    chunk_size: int = 64 * 1024,
    excluded: frozenset[OptionalLibrary] = NO_EXCLUSIONS,
) -> list[tuple[bytes, int]]:
    """Decrypt ``body`` with each password in parallel; return ``(password, crc32)``.

    ``body`` is the ZipCrypto ciphertext *after* the 12-byte encryption header: a stream
    over the member's payload positioned after that header; this function only reads
    forward. Constant memory beyond the current chunk: one ZipCrypto state and running
    CRC per candidate. Candidate order is preserved (ties resolved by the caller via
    first match).
    """
    states = [
        keys_after_header(password, header_ciphertext, excluded)[0]
        for password in passwords
    ]
    crcs = [0] * len(states)
    while True:
        chunk = body.read(chunk_size)
        if not chunk:
            break
        for i, keys in enumerate(states):
            crcs[i] = zlib.crc32(keys.decrypt(chunk), crcs[i])
    return [
        (password, crc & 0xFFFFFFFF)
        for password, crc in zip(passwords, crcs, strict=True)
    ]


class ZipCryptoDecryptStream(ReadOnlyIOStream):
    """The plaintext of one ZipCrypto member body: the decrypt stage ahead of the codec.

    ``source`` is the member's payload positioned just after the 12-byte header, ``keys``
    the cipher state after that header (:func:`keys_after_header`), and ``length`` the
    body's declared length (the member's compressed size less the header). Positions
    are plaintext offsets from the start of the body, which is the ciphertext offset
    too: ZipCrypto adds no bytes past the header.

    The cipher state depends on every earlier byte, so a backward seek restarts from
    the saved post-header state and a forward seek decrypts what it skips. The source
    must be seekable for the backward case. Seek positions follow
    :class:`~archivey.internal.streams.streamtools.SlicingStream` (and ``BytesIO``):
    only a negative ``SEEK_SET`` raises, a relative seek below 0 clamps to 0, and a
    seek past the end returns the requested position, where reads return ``b""``.
    ``read(n)`` is full-count: ``n`` bytes or what is left before the source ends.
    Close owns ``source``.
    """

    def __init__(
        self, source: BinaryIO, keys: ZipCryptoDecryptor, *, length: int
    ) -> None:
        # First: close() reads it, and IOBase.__del__ runs close() on a refused instance.
        self._source = source
        super().__init__()
        self._length = length
        self._start_keys = keys.copy()
        self._keys = keys
        self._pos = 0  # bytes decrypted so far
        self._logical = 0  # the caller's position; past ``_pos`` only after a seek
        self._origin = source.tell() if source.seekable() else 0

    @override
    def read(self, n: int = -1, /) -> bytes:
        if n == 0 or self._logical != self._pos:
            return b""
        data = (
            self._source.read() if n is None or n < 0 else read_exact(self._source, n)
        )
        if not data:
            return b""
        self._pos += len(data)
        self._logical = self._pos
        return self._keys.decrypt(data)

    @override
    def seekable(self) -> bool:
        return self._source.seekable()

    @override
    def tell(self) -> int:
        return self._logical

    @override
    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        target = resolve_seek(
            offset, whence, pos=self._logical, end=lambda: self._length
        )
        reach = min(target, self._length)
        if reach < self._pos:
            self._source.seek(self._origin)
            self._keys = self._start_keys.copy()
            self._pos = 0
        self._logical = self._pos
        while self._pos < reach:
            if not self.read(min(64 * 1024, reach - self._pos)):
                break  # the source ended early; reads from here return b""
        self._logical = target
        return target

    @override
    def close(self) -> None:
        if self.closed:
            return
        try:
            self._source.close()
        finally:
            super().close()
