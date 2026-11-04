"""Pure-Python CRC-32 combine (CPython adds a stdlib helper only in 3.15+).

This matches zlib's ``crc32_combine_``: given the digests of ``a`` and ``b`` plus
``len(b)``, return the digest of ``a + b`` without seeing the bytes. It surfaces
whole-stream digests from per-unit trailers (multi-member lzip).
"""

from __future__ import annotations

# ISO/zlib CRC-32 polynomial (reflected).
_CRC32_POLY = 0xEDB88320


def _multmodp(a: int, b: int) -> int:
    """``a * b mod P`` in the reflected bit order zlib uses (``a`` must be nonzero)."""
    m = 1 << 31
    p = 0
    while True:
        if a & m:
            p ^= b
            if (a & (m - 1)) == 0:
                return p
        m >>= 1
        b = (b >> 1) ^ _CRC32_POLY if b & 1 else b >> 1


def _x2n_table() -> tuple[int, ...]:
    # x^(2^k) mod P for k in 0..31, as zlib's ``x2n_table``.
    p = 1 << 30  # x^1
    table = [p]
    for _ in range(1, 32):
        p = _multmodp(p, p)
        table.append(p)
    return tuple(table)


_X2N_TABLE = _x2n_table()


def _x2nmodp(n: int, k: int) -> int:
    """``x^(n * 2^k) mod P``: one table multiply per set bit of ``n``."""
    p = 1 << 31  # x^0
    while n:
        if n & 1:
            p = _multmodp(_X2N_TABLE[k & 31], p)
        n >>= 1
        k += 1
    return p


# ``_BYTE_SHIFTS[i][b]`` is x^(8 * b * 256^i) mod P: the shift by ``b * 256^i`` zero
# bytes. Each row is built on first use (255 multiplies), so a shift by ``n`` bytes
# takes one multiply per nonzero byte of ``n`` instead of one per set bit.
_BYTE_SHIFTS: list[tuple[int, ...] | None] = [None] * 8


def _byte_shift_row(i: int) -> tuple[int, ...]:
    row = _BYTE_SHIFTS[i]
    if row is None:
        step = _x2nmodp(1 << (8 * i), 3)
        entries = [1 << 31, step]
        for _ in range(2, 256):
            entries.append(_multmodp(entries[-1], step))
        # A race builds the same row twice; either copy is right.
        row = _BYTE_SHIFTS[i] = tuple(entries)
    return row


def _shift_operator(len2: int) -> int:
    """x^(8 * len2) mod P, as ``_x2nmodp(len2, 3)`` gives it."""
    if len2 >> 64:
        return _x2nmodp(len2, 3)
    p = 1 << 31  # x^0
    i = 0
    while len2:
        b = len2 & 0xFF
        if b:
            p = _multmodp(_byte_shift_row(i)[b], p)
        len2 >>= 8
        i += 1
    return p


def crc32_combine(crc1: int, crc2: int, len2: int) -> int:
    """Return ``zlib.crc32(a + b)`` given ``crc32(a)``, ``crc32(b)``, and ``len(b)``.

    zlib 1.2.12+'s method: shift ``crc1`` by ``8 * len2`` zero bits. The shift is a
    product of precomputed powers of x, one per nonzero byte of ``len2``.
    """
    if len2 <= 0:
        return crc1 & 0xFFFFFFFF
    if crc1 & 0xFFFFFFFF == 0:
        return crc2 & 0xFFFFFFFF
    shifted = _multmodp(_shift_operator(len2), crc1 & 0xFFFFFFFF)
    return (shifted ^ (crc2 & 0xFFFFFFFF)) & 0xFFFFFFFF
