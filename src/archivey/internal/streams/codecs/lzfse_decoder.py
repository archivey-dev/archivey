"""LZFSE and LZVN, Apple's compression formats, decoded in Python.

An LZFSE stream is a sequence of blocks, each opened by a four-byte magic, and closed by
the end-of-stream block ``bvx$``:

- ``bvx-``: stored bytes;
- ``bvxn``: one LZVN payload, a byte-oriented LZ77 (literal, match and distance in each
  opcode);
- ``bvx1`` and ``bvx2``: LZFSE proper. Literals, and the literal length, match length
  and distance of each match, are coded with finite state entropy (tANS) and read
  backwards from the end of their payloads. ``bvx1`` stores its frequency tables as
  plain 16-bit counts, ``bvx2`` packs its header fields into 64-bit words and its
  tables into a variable-length code.

Raw LZVN, with no block header, is what HFS+ transparent compression (decmpfs types 7
and 8) stores: :func:`lzvn_decompress`.

The decoder follows Apple's reference implementation (``lzfse_decode_base.c``,
``lzvn_decode_base.c``, ``lzfse_fse.h``, BSD-3, github.com/lzfse/lzfse), and refuses
what it refuses. Where Apple's code lacks a check for clear damage, archivey refuses the
stream (``dev-docs/investigations/lzfse-package.md`` measured each case):

- a ``bvx1`` or ``bvx2`` block must decode to exactly its declared raw size (Apple
  holds only ``bvx-`` and ``bvxn`` blocks to it);
- a ``bvx1`` or ``bvx2`` block's literal count must be a multiple of 4, as every
  encoder writes it (Apple decodes the count rounded up);
- the matches of a block may use no more literals than it decoded (Apple checks only
  the size of its literal buffer, and copies whatever the buffer holds);
- a ``bvx1`` or ``bvx2`` block may hold no more literals than its raw size plus 3, and
  no more matches than its raw size (Apple bounds both only by fixed per-block limits,
  so a block that writes nothing could cost 10,000 iterations);
- nothing may follow the end-of-stream block or an LZVN end-of-stream opcode.

Every length is checked against the input before it is used, output never passes the
caller's ``max_length``, and a match may not reach back before the start of the
output. Every LZVN opcode consumes input. A ``bvx1`` or ``bvx2`` block costs one table
build, fixed by its frequencies, plus decode work bounded by its output. So the total
work is linear in the input and ``max_length``.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from typing import TYPE_CHECKING, Literal

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.types import OptionalLibrary

if TYPE_CHECKING:
    from archivey.config import ArchiveyConfig

_END = b"bvx$"
_STORED = b"bvx-"
_LZVN = b"bvxn"
_V1 = b"bvx1"
_V2 = b"bvx2"

_L_SYMBOLS, _M_SYMBOLS, _D_SYMBOLS, _LIT_SYMBOLS = 20, 20, 64, 256
_L_STATES, _M_STATES, _D_STATES, _LIT_STATES = 64, 64, 256, 1024
_MATCHES_PER_BLOCK = 10000
_LITERALS_PER_BLOCK = 4 * _MATCHES_PER_BLOCK
_SYMBOLS = _L_SYMBOLS + _M_SYMBOLS + _D_SYMBOLS + _LIT_SYMBOLS

_L_EXTRA = (0,) * 16 + (2, 3, 5, 8)
_L_BASE = tuple(range(16)) + (16, 20, 28, 60)
_M_EXTRA = (0,) * 16 + (3, 5, 8, 11)
_M_BASE = tuple(range(16)) + (16, 24, 56, 312)
_D_EXTRA = (0, 0, 0, 0) + tuple(1 + i // 4 for i in range(60))
_D_BASE = (
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156,
    188, 220, 252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044,
    2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476,
    24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684, 131068,
    163836, 196604, 229372,
)  # fmt: skip

# The v2 frequency code: the low 5 bits of the accumulator give the code's length and,
# for lengths up to 5, its value; 8- and 14-bit codes carry 4 and 10 value bits.
_FREQ_NBITS = (2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14) * 2
_FREQ_VALUE = (
    0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
    0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1,
)  # fmt: skip

_V1_HEADER = struct.Struct("<4s6Ii4HiHHH360H")  # 770 bytes of fields
_V1_SIZE = 772  # sizeof(lzfse_compressed_block_header_v1): padded to 4-byte alignment
_V2_FIXED = struct.Struct("<IQQQ")  # after the magic: n_raw and three packed words


def _too_long(max_length: int) -> CorruptionError:
    return CorruptionError(f"LZFSE data decodes to more than {max_length} bytes")


def lzfse_decompress(data: bytes, max_length: int) -> bytes:
    """Decode a whole LZFSE stream, which must end with ``bvx$`` and nothing after it.

    Raises :class:`TruncatedError` when the input ends before the stream does, and
    :class:`CorruptionError` for any other damage, including output past
    ``max_length``.
    """
    src = bytes(data)
    n = len(src)
    out = bytearray()
    pos = 0
    while True:
        if pos + 4 > n:
            raise TruncatedError("LZFSE stream ends before its end-of-stream block")
        magic = src[pos : pos + 4]
        if magic == _END:
            if pos + 4 != n:
                raise CorruptionError(
                    f"{n - pos - 4} bytes follow the end of the LZFSE stream"
                )
            return bytes(out)
        if magic == _STORED:
            if pos + 8 > n:
                raise TruncatedError("LZFSE stream ends inside a block header")
            (n_raw,) = struct.unpack_from("<I", src, pos + 4)
            if pos + 8 + n_raw > n:
                raise TruncatedError("LZFSE stream ends inside a stored block")
            if len(out) + n_raw > max_length:
                raise _too_long(max_length)
            out += src[pos + 8 : pos + 8 + n_raw]
            pos += 8 + n_raw
        elif magic == _LZVN:
            if pos + 12 > n:
                raise TruncatedError("LZFSE stream ends inside a block header")
            n_raw, n_payload = struct.unpack_from("<II", src, pos + 4)
            start = pos + 12
            if start + n_payload > n:
                raise TruncatedError("LZFSE stream ends inside an LZVN block")
            if len(out) + n_raw > max_length:
                raise _too_long(max_length)
            if n_raw == 0:
                raise CorruptionError("LZVN block declares no output")
            block_start = len(out)
            end = _lzvn(
                src,
                start,
                start + n_payload,
                out,
                block_start + n_raw,
                f"LZVN block decodes to more than its {n_raw} bytes",
            )
            if len(out) != block_start + n_raw:
                decoded = len(out) - block_start
                raise CorruptionError(
                    f"LZVN block decodes to {decoded} bytes, its header says {n_raw}"
                )
            if end != start + n_payload:
                raise CorruptionError(
                    f"{start + n_payload - end} bytes follow the end of an LZVN block"
                )
            pos = start + n_payload
        elif magic == _V1 or magic == _V2:
            pos = _fse_block(src, pos, magic == _V2, out, max_length)
        else:
            raise CorruptionError(f"unknown LZFSE block magic {magic!r}")


Decode = Callable[[bytes, int], bytes]


def decoder(
    kernel: Literal["lzfse", "lzvn"],
    excluded: frozenset[OptionalLibrary],
    *,
    isolated: bool,
) -> Decode:
    """The LZFSE or the raw LZVN decoder to use: archivey-codecs' ``kernel`` when
    :mod:`archivey.internal.kernels` allows it (installed, not in ``excluded``, not
    ``isolated`` under ``NATIVE_DECODERS``), else :func:`lzfse_decompress` or
    :func:`lzvn_decompress`. Both give the same bytes and the same errors."""
    # Imported here: the kernels' Python twins import this module.
    from archivey.internal import kernels

    switch = kernels.lzfse if kernel == "lzfse" else kernels.lzvn
    chosen = switch(excluded, isolated=isolated)
    if chosen.library is None:
        return lzfse_decompress if kernel == "lzfse" else lzvn_decompress
    decompress = chosen.decompress

    def decode(data: bytes, max_length: int) -> bytes:
        return decompress(data, max_size=max_length)

    return decode


def decoder_for(kernel: Literal["lzfse", "lzvn"], config: ArchiveyConfig) -> Decode:
    """:func:`decoder` for a reader's call: its policy's switched-off packages, and
    whether its ``process_isolation`` is ``NATIVE_DECODERS``."""
    # Imported here: archivey.config imports the codecs package.
    from archivey.config import ProcessIsolation

    return decoder(
        kernel,
        config.formats._libraries_off,
        isolated=config.process_isolation is ProcessIsolation.NATIVE_DECODERS,
    )


def lzvn_decompress(data: bytes, max_length: int) -> bytes:
    """Decode raw LZVN, as decmpfs types 7 and 8 store it: opcodes up to the
    end-of-stream opcode, and nothing after it."""
    src = bytes(data)
    out = bytearray()
    end = _lzvn(
        src,
        0,
        len(src),
        out,
        max_length,
        f"LZVN data decodes to more than {max_length} bytes",
    )
    if end != len(src):
        raise CorruptionError(f"{len(src) - end} bytes follow the end of the LZVN data")
    return bytes(out)


def _lzvn(src: bytes, i: int, n: int, out: bytearray, limit: int, overrun: str) -> int:
    """Decode LZVN from ``src[i:n]`` onto ``out`` up to its end-of-stream opcode; return
    the offset just past that opcode. ``out`` may already hold earlier output, which
    matches can reach back into, and may not grow past ``limit``: past it, the
    ``CorruptionError`` says ``overrun``. ``d`` starts at 0, which no match may use."""
    d = 0
    while True:
        if i >= n:
            raise TruncatedError("LZVN data ends before its end-of-stream opcode")
        op = src[i]
        hi = op >> 4
        lit = mlen = 0
        if hi < 0xA or hi == 0xC:
            low = op & 7
            if low == 6:
                if op < 0x40:
                    if op == 0x06:  # end of stream: the opcode and 7 bytes after it
                        if i + 8 > n:
                            raise TruncatedError("LZVN data ends inside its end marker")
                        return i + 8
                    if op == 0x0E or op == 0x16:  # nop
                        i += 1
                        continue
                    raise CorruptionError(f"undefined LZVN opcode {op:#04x}")
                if hi == 0x7:
                    raise CorruptionError(f"undefined LZVN opcode {op:#04x}")
                # pre_d: LLMMM110, the previous distance
                lit = op >> 6
                mlen = ((op >> 3) & 7) + 3
                i += 1
            elif hi == 0x7:
                raise CorruptionError(f"undefined LZVN opcode {op:#04x}")
            elif low == 7:  # lrg_d: LLMMM111 DDDDDDDD DDDDDDDD
                if i + 3 > n:
                    raise TruncatedError("LZVN data ends inside an opcode")
                lit = op >> 6
                mlen = ((op >> 3) & 7) + 3
                d = src[i + 1] | (src[i + 2] << 8)
                i += 3
            else:  # sml_d: LLMMMDDD DDDDDDDD
                if i + 2 > n:
                    raise TruncatedError("LZVN data ends inside an opcode")
                lit = op >> 6
                mlen = ((op >> 3) & 7) + 3
                d = (low << 8) | src[i + 1]
                i += 2
        elif hi == 0xA or hi == 0xB:  # med_d: 101LLMMM DDDDDDMM DDDDDDDD
            if i + 3 > n:
                raise TruncatedError("LZVN data ends inside an opcode")
            b1 = src[i + 1]
            lit = (op >> 3) & 3
            mlen = (((op & 7) << 2) | (b1 & 3)) + 3
            d = (src[i + 2] << 6) | (b1 >> 2)
            i += 3
        elif hi == 0xD:
            raise CorruptionError(f"undefined LZVN opcode {op:#04x}")
        elif hi == 0xE:  # literal only: 1110LLLL, or 11100000 LLLLLLLL
            if op == 0xE0:
                if i + 2 > n:
                    raise TruncatedError("LZVN data ends inside an opcode")
                lit = src[i + 1] + 16
                i += 2
            else:
                lit = op & 0xF
                i += 1
        else:  # match only, previous distance: 1111MMMM, or 11110000 MMMMMMMM
            if op == 0xF0:
                if i + 2 > n:
                    raise TruncatedError("LZVN data ends inside an opcode")
                mlen = src[i + 1] + 16
                i += 2
            else:
                mlen = op & 0xF
                i += 1
        if lit:
            if i + lit > n:
                raise TruncatedError("LZVN data ends inside a literal")
            if len(out) + lit > limit:
                raise CorruptionError(overrun)
            out += src[i : i + lit]
            i += lit
        if mlen:
            size = len(out)
            if d == 0 or d > size:
                raise CorruptionError(
                    "LZVN match reaches before the start of the output"
                )
            if size + mlen > limit:
                raise CorruptionError(overrun)
            _copy_match(out, d, mlen)


def _copy_match(out: bytearray, d: int, mlen: int) -> None:
    """Append ``mlen`` bytes copied from ``d`` bytes back, byte by byte in effect: a
    match may overlap its own output."""
    start = len(out) - d
    if d >= mlen:
        out += out[start : start + mlen]
    else:
        chunk = out[start:]
        reps, rest = divmod(mlen, d)
        out += chunk * reps + chunk[:rest]


def _decoder_table(
    nstates: int, freq: tuple[int, ...] | list[int], what: str
) -> list[int]:
    """A literal decoder table: per state, ``(delta << 16) | (symbol << 8) | k``, as
    ``fse_init_decoder_table`` builds it. States no symbol fills stay 0."""
    table = [0] * nstates
    total = 0
    nb = nstates.bit_length()
    s = 0
    for sym, f in enumerate(freq):
        if f == 0:
            continue
        total += f
        if total > nstates:
            raise CorruptionError(f"LZFSE {what} frequencies exceed {nstates} states")
        k = nb - f.bit_length()
        j0 = ((2 * nstates) >> k) - f
        for j in range(f):
            if j < j0:
                table[s] = ((((f + j) << k) - nstates) << 16) | (sym << 8) | k
            else:
                table[s] = (((j - j0) << (k - 1)) << 16) | (sym << 8) | (k - 1)
            s += 1
    return table


def _value_table(
    nstates: int,
    freq: tuple[int, ...] | list[int],
    vbits: tuple[int, ...],
    vbase: tuple[int, ...],
    what: str,
) -> list[tuple[int, int, int, int]]:
    """A value decoder table: per state ``(total bits, value bits, delta, base)``, as
    ``fse_init_value_decoder_table`` builds it. States no symbol fills stay zero."""
    table = [(0, 0, 0, 0)] * nstates
    total = 0
    nb = nstates.bit_length()
    s = 0
    for sym, f in enumerate(freq):
        if f == 0:
            continue
        total += f
        if total > nstates:
            raise CorruptionError(f"LZFSE {what} frequencies exceed {nstates} states")
        k = nb - f.bit_length()
        j0 = ((2 * nstates) >> k) - f
        vb = vbits[sym]
        base = vbase[sym]
        for j in range(f):
            if j < j0:
                table[s] = (k + vb, vb, ((f + j) << k) - nstates, base)
            else:
                table[s] = (k - 1 + vb, vb, (j - j0) << (k - 1), base)
            s += 1
    return table


class _BackBits:
    """The first load of an ``fse_in_stream`` (the 64-bit variant), read backwards from
    ``end``; the decode loops refill it themselves, never from before the input's
    start."""

    __slots__ = ("accum", "nbits", "pos")

    def __init__(self, buf: bytes, start: int, end: int, n: int) -> None:
        # fse_in_checked_init64: the first load may not pass ``start``; the refills may
        # read back to the start of the input, for the literal and the match streams
        # alike, as in Apple's decoder.
        width = 8 if n else 7
        if end < start + width:
            raise CorruptionError("LZFSE bit stream is shorter than its first load")
        end -= width
        self.accum = int.from_bytes(buf[end : end + width], "little")
        self.nbits = n + width * 8
        self.pos = end
        if not 56 <= self.nbits < 64 or self.accum >> self.nbits:
            raise CorruptionError("LZFSE bit stream starts with bad padding")


def _v2_frequencies(src: bytes, p: int, end: int) -> list[int]:
    """The 360 frequencies of a ``bvx2`` header, from ``src[p:end]``; none at all (an
    empty table area) means every frequency is 0, as ``lzfse_decode_v1`` reads it."""
    if p == end:
        return [0] * _SYMBOLS
    freq = []
    accum = nbits = 0
    for _ in range(_SYMBOLS):
        while p < end and nbits + 8 <= 32:
            accum |= src[p] << nbits
            nbits += 8
            p += 1
        b = accum & 31
        width = _FREQ_NBITS[b]
        if width == 8:
            value = 8 + ((accum >> 4) & 0xF)
        elif width == 14:
            value = 24 + ((accum >> 4) & 0x3FF)
        else:
            value = _FREQ_VALUE[b]
        if width > nbits:
            raise CorruptionError("LZFSE frequency table ends early")
        freq.append(value)
        accum >>= width
        nbits -= width
    if nbits >= 8 or p != end:
        raise CorruptionError("LZFSE frequency table has bytes left over")
    return freq


def _fse_block(src: bytes, pos: int, v2: bool, out: bytearray, max_length: int) -> int:
    """Decode the ``bvx1`` or ``bvx2`` block at ``pos`` onto ``out``; return the offset
    after it."""
    n = len(src)
    if v2:
        if pos + 4 + _V2_FIXED.size > n:
            raise TruncatedError("LZFSE stream ends inside a block header")
        n_raw, p0, p1, p2 = _V2_FIXED.unpack_from(src, pos + 4)
        n_literals = p0 & 0xFFFFF
        n_lit_payload = (p0 >> 20) & 0xFFFFF
        n_matches = (p0 >> 40) & 0xFFFFF
        literal_bits = ((p0 >> 60) & 7) - 7
        lit_state = [(p1 >> s) & 0x3FF for s in (0, 10, 20, 30)]
        n_lmd_payload = (p1 >> 40) & 0xFFFFF
        lmd_bits = ((p1 >> 60) & 7) - 7
        header_size = p2 & 0xFFFFFFFF
        l_state, m_state, d_state = (
            (p2 >> 32) & 0x3FF,
            (p2 >> 42) & 0x3FF,
            (p2 >> 52) & 0x3FF,
        )
        if header_size < 4 + _V2_FIXED.size:
            raise CorruptionError(f"LZFSE block header of {header_size} bytes")
        if pos + header_size > n:
            raise TruncatedError("LZFSE stream ends inside a block header")
        freq = _v2_frequencies(src, pos + 4 + _V2_FIXED.size, pos + header_size)
    else:
        if pos + _V1_SIZE > n:
            raise TruncatedError("LZFSE stream ends inside a block header")
        fields = _V1_HEADER.unpack_from(src, pos)
        (
            _magic,
            n_raw,
            _n_payload,  # the sum of the next two; Apple's decoder does not read it
            n_literals,
            n_matches,
            n_lit_payload,
            n_lmd_payload,
            literal_bits,
            *lit_state_and_rest,
        ) = fields
        lit_state = list(lit_state_and_rest[:4])
        lmd_bits, l_state, m_state, d_state = lit_state_and_rest[4:8]
        freq = list(lit_state_and_rest[8:])
        header_size = _V1_SIZE
    if n_literals > _LITERALS_PER_BLOCK or n_matches > _MATCHES_PER_BLOCK:
        raise CorruptionError("LZFSE block holds more literals or matches than allowed")
    if n_literals % 4:
        raise CorruptionError(
            f"LZFSE block literal count {n_literals} is not a multiple of 4"
        )
    # Every literal a match uses is one output byte, and every match an encoder writes
    # makes at least one, so these tie the block's work to its output.
    if n_literals > n_raw + 3:
        raise CorruptionError(
            f"LZFSE block has {n_literals} literals for {n_raw} bytes of output"
        )
    if n_matches > n_raw:
        raise CorruptionError(
            f"LZFSE block has {n_matches} matches for {n_raw} bytes of output"
        )
    if (
        max(lit_state) >= _LIT_STATES
        or l_state >= _L_STATES
        or m_state >= _M_STATES
        or d_state >= _D_STATES
    ):
        raise CorruptionError("LZFSE block starts in a state out of range")
    lit_end = pos + header_size + n_lit_payload
    lmd_end = lit_end + n_lmd_payload
    if lmd_end > n:
        raise TruncatedError("LZFSE stream ends inside a block")
    if len(out) + n_raw > max_length:
        raise _too_long(max_length)

    l_table = _value_table(_L_STATES, freq[:20], _L_EXTRA, _L_BASE, "literal length")
    m_table = _value_table(_M_STATES, freq[20:40], _M_EXTRA, _M_BASE, "match length")
    d_table = _value_table(_D_STATES, freq[40:104], _D_EXTRA, _D_BASE, "distance")
    lit_table = _decoder_table(_LIT_STATES, freq[104:], "literal")

    # Literals: four interleaved states, read backwards from the end of their payload.
    bits = _BackBits(src, 0, lit_end, literal_bits)
    accum, nbits, bpos = bits.accum, bits.nbits, bits.pos
    literals = bytearray(n_literals)
    s0, s1, s2, s3 = lit_state
    from_bytes = int.from_bytes
    for i in range(0, n_literals, 4):
        take = (63 - nbits) & ~7
        if take:  # fse_in_checked_flush64
            bpos -= take >> 3
            if bpos < 0:
                raise CorruptionError(
                    "LZFSE bit stream reads before the start of the input"
                )
            accum = (accum << take) | (
                from_bytes(src[bpos : bpos + 8], "little") & ((1 << take) - 1)
            )
            nbits += take
        # Four symbols of at most 10 bits each fit in the 56 or more bits just loaded.
        e = lit_table[s0]
        nbits -= e & 0xFF
        s0 = (e >> 16) + (accum >> nbits)
        accum &= (1 << nbits) - 1
        literals[i] = (e >> 8) & 0xFF
        e = lit_table[s1]
        nbits -= e & 0xFF
        s1 = (e >> 16) + (accum >> nbits)
        accum &= (1 << nbits) - 1
        literals[i + 1] = (e >> 8) & 0xFF
        e = lit_table[s2]
        nbits -= e & 0xFF
        s2 = (e >> 16) + (accum >> nbits)
        accum &= (1 << nbits) - 1
        literals[i + 2] = (e >> 8) & 0xFF
        e = lit_table[s3]
        nbits -= e & 0xFF
        s3 = (e >> 16) + (accum >> nbits)
        accum &= (1 << nbits) - 1
        literals[i + 3] = (e >> 8) & 0xFF

    # Literal length, match length, distance: one triple per match. One refill per
    # triple, as Apple's 64-bit decoder does: it leaves at least 56 bits, and a triple
    # takes at most 14 + 17 + 23 (state bits plus extra bits of each field).
    bits = _BackBits(src, lit_end, lmd_end, lmd_bits)
    accum, nbits, bpos = bits.accum, bits.nbits, bits.pos
    block_start = len(out)
    block_limit = block_start + n_raw
    used = 0
    d = -1  # Apple's "illegal previous distance": a first triple must bring its own
    for _ in range(n_matches):
        take = (63 - nbits) & ~7
        if take:
            bpos -= take >> 3
            if bpos < 0:
                raise CorruptionError(
                    "LZFSE bit stream reads before the start of the input"
                )
            accum = (accum << take) | (
                from_bytes(src[bpos : bpos + 8], "little") & ((1 << take) - 1)
            )
            nbits += take
        tb, vb, delta, base = l_table[l_state]
        nbits -= tb
        v = accum >> nbits
        accum &= (1 << nbits) - 1
        l_state = delta + (v >> vb)
        lit_len = base + (v & ((1 << vb) - 1))
        tb, vb, delta, base = m_table[m_state]
        nbits -= tb
        v = accum >> nbits
        accum &= (1 << nbits) - 1
        m_state = delta + (v >> vb)
        match_len = base + (v & ((1 << vb) - 1))
        tb, vb, delta, base = d_table[d_state]
        nbits -= tb
        v = accum >> nbits
        accum &= (1 << nbits) - 1
        d_state = delta + (v >> vb)
        new_d = base + (v & ((1 << vb) - 1))
        if new_d:
            d = new_d
        # As lzfse_decode_lmd: every triple's distance must lie within the output
        # once its literals are written, whether or not it has a match.
        size = len(out)
        if d < 0 or d > size + lit_len:
            raise CorruptionError("LZFSE match reaches before the start of the output")
        if used + lit_len > n_literals:
            raise CorruptionError("LZFSE block uses more literals than it decoded")
        if size + lit_len + match_len > block_limit:
            raise CorruptionError(f"LZFSE block decodes to more than its {n_raw} bytes")
        if lit_len:
            out += literals[used : used + lit_len]
            used += lit_len
        if match_len:
            if d >= match_len:
                start = size + lit_len - d
                out += out[start : start + match_len]
            else:
                _copy_match(out, d, match_len)
    if len(out) != block_limit:
        raise CorruptionError(
            f"LZFSE block decodes to {len(out) - block_start} bytes, its header says {n_raw}"
        )
    return lmd_end
