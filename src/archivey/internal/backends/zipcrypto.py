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

import functools
import io
import zlib
from collections.abc import Sequence
from typing import BinaryIO

from archivey.internal.overrides import override
from archivey.internal.streams.streamtools import (
    ReadOnlyIOStream,
    read_exact,
    resolve_seek,
)

#: Length of the encryption header in front of every ZipCrypto member's data.
ZIPCRYPTO_HEADER_LEN = 12


def _make_crc_table() -> list[int]:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if (c & 1) else (c >> 1)
        table.append(c)
    return table


_CRC_TABLE = _make_crc_table()

# Each CRC table entry split into its low byte and its upper 24 bits, for the split-k0
# update in :meth:`ZipCryptoKeys.decrypt`.
_CRC_TABLE_LOW_BYTE = [v & 0xFF for v in _CRC_TABLE]
_CRC_TABLE_HIGH_BITS = [v >> 8 for v in _CRC_TABLE]


@functools.cache
def _keystream_table() -> bytes:
    """The keystream byte for every value of ``k2 & 0xFFFF``.

    APPNOTE §6.1.5 defines the keystream byte as ``((t * (t ^ 1)) >> 8) & 0xFF`` with
    ``t = (k2 | 2) & 0xFFFF``. Only bits 8..15 of the product survive, and they depend
    only on the low 16 bits of ``t``, so a 64 KiB table indexed by ``k2 & 0xFFFF``
    replaces the multiply.

    Bits 0 and 1 of ``k2`` do not matter either. ``| 2`` forces bit 1 on. Bit 0 only
    picks which neighbour ``t ^ 1`` is: with bit 0 clear the product is ``t * (t + 1)``,
    with it set it is ``(t - 1) * t``, the same pair. So every group of four
    consecutive indices ``4j .. 4j + 3`` shares the value computed at ``t = 4j + 2``.

    Built on first use rather than at import: this module is imported with every
    ZIP reader, and most processes never decrypt a ZipCrypto member.
    """
    per_group = bytes(((t * (t + 1)) >> 8) & 0xFF for t in range(2, 0x10000, 4))
    table = bytearray(0x10000)
    for low_bits in range(4):
        table[low_bits::4] = per_group
    return bytes(table)


# decrypt() collects plaintext as a list of ints; bounding the list per chunk keeps
# its memory small (a list costs ~8 bytes per element, the bytes result one).
_DECRYPT_CHUNK = 16 * 1024


class ZipCryptoKeys:
    """The 96-bit ZipCrypto key state."""

    __slots__ = ("k0", "k1", "k2")

    def __init__(self, password: bytes) -> None:
        # APPNOTE §6.1.5 update_keys, run over the password bytes (plain, not decrypted).
        # No 32-bit masks on k0/k2: see the width note in decrypt().
        k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
        table = _CRC_TABLE
        for b in password:
            k0 = (k0 >> 8) ^ table[(k0 ^ b) & 0xFF]
            k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            k2 = (k2 >> 8) ^ table[(k2 ^ (k1 >> 24)) & 0xFF]
        self.k0, self.k1, self.k2 = k0, k1, k2

    def copy(self) -> ZipCryptoKeys:
        clone = ZipCryptoKeys.__new__(ZipCryptoKeys)
        clone.k0, clone.k1, clone.k2 = self.k0, self.k1, self.k2
        return clone

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt ``data`` and advance the state past it.

        This loop is the whole cost of reading a ZipCrypto member, so it runs on local
        variables with three rewrites of APPNOTE §6.1.5 that give the same bytes:

        * The keystream byte is a lookup in :func:`_keystream_table` instead of a
          multiply.
        * ``k0`` is held split, as ``k0_low`` (its low byte) and ``k0_high`` (the upper
          24 bits). The CRC step ``k0 = (k0 >> 8) ^ crc[(k0 ^ c) & 0xFF]`` becomes a
          byte update and a 24-bit update with pre-split table halves, and ``k1``
          reads ``k0 & 0xFF`` as ``k0_low`` directly, with no mask or recombining.
          ``k0`` is reassembled once, at the end.
        * The ``k2`` index ``(k2 ^ (k1 >> 24)) & 0xFF`` becomes
          ``(k2 & 0xFF) ^ (k1 >> 24)``, masking ``k2`` alone.

        The dropped masks rely on two widths. ``k1`` is masked to 32 bits every step,
        so ``k1 >> 24`` is already a byte and the ``k2`` index needs no outer mask.
        CRC table entries are at most 32 bits, so ``k0`` and ``k2`` stay 32-bit
        through ``(x >> 8) ^ entry`` and ``k0_high`` stays 24-bit, which is why the
        reassembly needs no mask either. Removing the ``k1`` mask would break both.
        """
        crc, crc_low, crc_high = _CRC_TABLE, _CRC_TABLE_LOW_BYTE, _CRC_TABLE_HIGH_BITS
        keystream = _keystream_table()
        k1, k2 = self.k1, self.k2
        k0_high, k0_low = self.k0 >> 8, self.k0 & 0xFF
        parts = []
        for start in range(0, len(data), _DECRYPT_CHUNK):
            out = []
            for c in data[start : start + _DECRYPT_CHUNK]:
                c ^= keystream[k2 & 0xFFFF]
                out.append(c)
                i = k0_low ^ c
                k0_low = (k0_high & 0xFF) ^ crc_low[i]
                k0_high = (k0_high >> 8) ^ crc_high[i]
                k1 = ((k1 + k0_low) * 134775813 + 1) & 0xFFFFFFFF
                k2 = (k2 >> 8) ^ crc[(k2 & 0xFF) ^ (k1 >> 24)]
            parts.append(bytes(out))
        self.k0, self.k1, self.k2 = (k0_high << 8) | k0_low, k1, k2
        return b"".join(parts)


def keys_after_header(
    password: bytes, header_ciphertext: bytes
) -> tuple[ZipCryptoKeys, int]:
    """Decrypt the 12-byte header; return the state after it and its last plaintext byte.

    The last byte is the check byte a correct password reproduces.
    """
    keys = ZipCryptoKeys(password)
    plain = keys.decrypt(header_ciphertext[:ZIPCRYPTO_HEADER_LEN])
    return keys, plain[-1]


def password_matches_check_byte(
    password: bytes, header_ciphertext: bytes, check_byte: int
) -> bool:
    """Whether ``password`` satisfies ZipCrypto's 1-byte header check.

    ``header_ciphertext`` must be the first 12 encrypted bytes of the member.
    """
    if len(header_ciphertext) < ZIPCRYPTO_HEADER_LEN:
        return False
    _, plain_last = keys_after_header(password, header_ciphertext)
    return plain_last == check_byte


def parallel_plaintext_crc32(
    passwords: Sequence[bytes],
    header_ciphertext: bytes,
    body: BinaryIO,
    *,
    chunk_size: int = 64 * 1024,
) -> list[tuple[bytes, int]]:
    """Decrypt ``body`` with each password in parallel; return ``(password, crc32)``.

    ``body`` is the ZipCrypto ciphertext *after* the 12-byte encryption header: a stream
    over the member's payload positioned after that header; this function only reads
    forward. Constant memory beyond the current chunk: one ZipCrypto state and running
    CRC per candidate. Candidate order is preserved (ties resolved by the caller via
    first match).
    """
    states = [
        keys_after_header(password, header_ciphertext)[0] for password in passwords
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

    def __init__(self, source: BinaryIO, keys: ZipCryptoKeys, *, length: int) -> None:
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
