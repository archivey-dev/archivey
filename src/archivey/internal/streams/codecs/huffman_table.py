"""Two-level decoding tables for canonical Huffman codes read most significant bit
first, as LZX and LHA store them.

A code assigns its codes in order of length, then of symbol, starting from all zeros,
so the shortest codes come first. Every code is at most 16 bits. Each table is a root
indexed by the next ``min(longest code, 10)`` bits and, under each root entry whose
codes are longer, a sub-table as wide as the longest of them. A stream may rebuild its
tables often (an LZX or LHA block can be nearly empty), so the cost of a build follows
the code it decodes, not the 65 536 entries a one-level 16-bit table would fill.
"""

from __future__ import annotations

from itertools import compress

from archivey.exceptions import CorruptionError

MAX_CODE = 16
ROOT_BITS = 10

Tree = tuple[list[int], int]
"""A decoding table and its root width in bits.

A root entry ``symbol << 5 | length`` decodes a code of ``length`` bits. A negative
root entry ``~(start << 5 | bits)`` points to a sub-table at ``start``, indexed by the
``bits`` bits after the root's; its entries hold the length past the root.
"""


def build_table(
    lengths: list[int], count: int, what: str, *, may_be_empty: bool = True
) -> Tree | None:
    """The two-level decoding table for the canonical code of ``lengths[:count]``.

    A length above ``MAX_CODE`` (an LZX delta that wrapped below 0) gives its symbol no
    code. ``None`` for a tree whose lengths are all 0 when ``may_be_empty``; a code
    that overfills or underfills the code space is damage, and so is any other empty
    tree.
    """
    by_length: list[list[int]] = [[] for _ in range(MAX_CODE + 1)]
    nonzero = False
    for symbol in compress(range(count), lengths[:count]):
        nonzero = True
        if lengths[symbol] <= MAX_CODE:
            by_length[lengths[symbol]].append(symbol)
    if not nonzero:
        if may_be_empty:
            return None
        raise CorruptionError(f"{what} tree has no codes")
    longest = max((n for n in range(1, MAX_CODE + 1) if by_length[n]), default=0)
    if not longest:
        raise CorruptionError(f"{what} tree does not fill its code space")
    root = min(longest, ROOT_BITS)
    # ``pos`` is where the next code starts, in units of 2**-16 of the code space.
    full = 1 << MAX_CODE
    shift = MAX_CODE - root
    pos = 0
    table = [0] * (1 << root)
    # Codes past the root, in code order: (start, length, symbol).
    long_codes: list[tuple[int, int, int]] = []
    for length in range(1, longest + 1):
        span = 1 << (MAX_CODE - length)
        symbols = by_length[length]
        if pos + span * len(symbols) > full:
            raise CorruptionError(f"{what} tree overfills its code space")
        if length <= root:
            fill = 1 << (root - length)
            for symbol in symbols:
                at = pos >> shift
                table[at : at + fill] = [symbol << 5 | length] * fill
                pos += span
        else:
            for symbol in symbols:
                long_codes.append((pos, length, symbol))
                pos += span
    if pos != full:
        raise CorruptionError(f"{what} tree does not fill its code space")
    # Codes come in length order, so those under one root entry are consecutive and
    # the last is the longest: the sub-table is as wide as it needs.
    low = (1 << shift) - 1
    i = 0
    while i < len(long_codes):
        prefix = long_codes[i][0] >> shift
        j = i
        while j + 1 < len(long_codes) and long_codes[j + 1][0] >> shift == prefix:
            j += 1
        bits = long_codes[j][1] - root
        start = len(table)
        table += [0] * (1 << bits)
        table[prefix] = ~(start << 5 | bits)
        for code_pos, length, symbol in long_codes[i : j + 1]:
            at = start + ((code_pos & low) >> (shift - bits))
            fill = 1 << (root + bits - length)
            table[at : at + fill] = [symbol << 5 | (length - root)] * fill
        i = j + 1
    return table, root
