"""ZipCrypto (PKWARE's traditional ZIP cipher) in Python, as
``archivey_codecs.zipcrypto``: APPNOTE.txt §6.1, a 96-bit key state seeded from the
password, each byte XORed with a keystream byte derived from the evolving state."""

from __future__ import annotations

import functools

from archivey.internal.kernels.python._buffers import raw_bytes


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
# update in :meth:`Decryptor.decrypt`.
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


class Decryptor:
    """The 96-bit ZipCrypto key state, as ``archivey_codecs.zipcrypto.Decryptor``."""

    __slots__ = ("k0", "k1", "k2", "total_in")

    def __init__(self, password: bytes | bytearray | memoryview) -> None:
        # APPNOTE §6.1.5 update_keys, run over the password bytes (plain, not decrypted).
        # No 32-bit masks on k0/k2: see the width note in decrypt().
        k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890
        table = _CRC_TABLE
        for b in raw_bytes(password):
            k0 = (k0 >> 8) ^ table[(k0 ^ b) & 0xFF]
            k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
            k2 = (k2 >> 8) ^ table[(k2 ^ (k1 >> 24)) & 0xFF]
        self.k0, self.k1, self.k2 = k0, k1, k2
        self.total_in = 0  # bytes decrypted

    def copy(self) -> Decryptor:
        clone = Decryptor.__new__(Decryptor)
        clone.k0, clone.k1, clone.k2 = self.k0, self.k1, self.k2
        clone.total_in = self.total_in
        return clone

    def decrypt(self, data: bytes | bytearray | memoryview) -> bytes:
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
        data = raw_bytes(data)
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
        self.total_in += len(data)
        return b"".join(parts)
