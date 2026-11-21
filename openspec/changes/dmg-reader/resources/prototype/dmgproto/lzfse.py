"""Pure-Python LZFSE and LZVN decoders (prototype), written from the format as Apple's
BSD-3 reference implementation (github.com/lzfse/lzfse) defines it."""

from __future__ import annotations

import struct


class LzfseError(Exception):
    pass


ENDOFSTREAM = 0x24787662  # bvx$
UNCOMPRESSED = 0x2D787662  # bvx-
V1 = 0x31787662  # bvx1
V2 = 0x32787662  # bvx2
LZVN = 0x6E787662  # bvxn

L_SYMBOLS, M_SYMBOLS, D_SYMBOLS, LIT_SYMBOLS = 20, 20, 64, 256
L_STATES, M_STATES, D_STATES, LIT_STATES = 64, 64, 256, 1024
MATCHES_PER_BLOCK = 10000
LITERALS_PER_BLOCK = 4 * MATCHES_PER_BLOCK

L_EXTRA = [0] * 16 + [2, 3, 5, 8]
L_BASE = list(range(16)) + [16, 20, 28, 60]
M_EXTRA = [0] * 16 + [3, 5, 8, 11]
M_BASE = list(range(16)) + [16, 24, 56, 312]
D_EXTRA = [i // 4 if i >= 4 else 0 for i in range(64)]
D_EXTRA[4:8] = [1, 1, 1, 1]
D_EXTRA = [0, 0, 0, 0] + [1 + (i // 4) for i in range(60)]
D_BASE = [0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156,
          188, 220, 252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044,
          2556, 3068, 3580, 4092, 5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476,
          24572, 28668, 32764, 40956, 49148, 57340, 65532, 81916, 98300, 114684, 131068,
          163836, 196604, 229372]

_FREQ_NBITS = [2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14] * 2
_FREQ_VALUE = [0, 2, 1, 4, 0, 3, 1, -1, 0, 2, 1, 5, 0, 3, 1, -1,
               0, 2, 1, 6, 0, 3, 1, -1, 0, 2, 1, 7, 0, 3, 1, -1]


def _bitlen(x: int) -> int:
    return x.bit_length()


def _decoder_table(nstates: int, freq: list[int]) -> list[tuple[int, int, int]]:
    """Literal decoder: per state (k, symbol, delta)."""
    t: list[tuple[int, int, int]] = []
    total = 0
    nb = _bitlen(nstates)
    for sym, f in enumerate(freq):
        if f == 0:
            continue
        total += f
        if total > nstates:
            raise LzfseError("frequencies exceed state count")
        k = nb - _bitlen(f)
        j0 = ((2 * nstates) >> k) - f
        for j in range(f):
            if j < j0:
                t.append((k, sym, ((f + j) << k) - nstates))
            else:
                t.append((k - 1, sym, (j - j0) << (k - 1)))
    if len(t) < nstates:
        t.extend([(0, 0, 0)] * (nstates - len(t)))  # unreachable states in a valid stream
    return t


def _value_table(nstates: int, freq: list[int], vbits: list[int], vbase: list[int]):
    """Value decoder: per state (total_bits, value_bits, delta, vbase)."""
    t = []
    total = 0
    nb = _bitlen(nstates)
    for sym, f in enumerate(freq):
        if f == 0:
            continue
        total += f
        if total > nstates:
            raise LzfseError("frequencies exceed state count")
        k = nb - _bitlen(f)
        j0 = ((2 * nstates) >> k) - f
        vb = vbits[sym]
        for j in range(f):
            if j < j0:
                t.append((k + vb, vb, ((f + j) << k) - nstates, vbase[sym]))
            else:
                t.append((k - 1 + vb, vb, (j - j0) << (k - 1), vbase[sym]))
    if len(t) < nstates:
        t.extend([(0, 0, 0, 0)] * (nstates - len(t)))
    return t


class _BackBits:
    """fse_in_stream (64-bit variant): read backwards from ``end`` towards ``start``."""

    __slots__ = ("buf", "start", "pos", "accum", "nbits")

    def __init__(self, buf: bytes, start: int, end: int, n: int) -> None:
        self.buf, self.start = buf, start
        if n:
            if end < start + 8:
                raise LzfseError("bit stream too short")
            end -= 8
            self.accum = int.from_bytes(buf[end:end + 8], "little")
            self.nbits = n + 64
        else:
            if end < start + 7:
                raise LzfseError("bit stream too short")
            end -= 7
            self.accum = int.from_bytes(buf[end:end + 7], "little")
            self.nbits = n + 56
        self.pos = end
        if not (56 <= self.nbits < 64) or (self.accum >> self.nbits):
            raise LzfseError("bad bit stream start")

    def flush(self) -> None:
        nbits = (63 - self.nbits) & ~7
        if not nbits:
            return
        p = self.pos - (nbits >> 3)
        if p < self.start:
            raise LzfseError("bit stream underflow")
        self.pos = p
        incoming = int.from_bytes(self.buf[p:p + 8], "little") & ((1 << nbits) - 1)
        self.accum = (self.accum << nbits) | incoming
        self.nbits += nbits

    def pull(self, n: int) -> int:
        self.nbits -= n
        if self.nbits < 0:
            raise LzfseError("bit stream overrun")
        r = self.accum >> self.nbits
        self.accum &= (1 << self.nbits) - 1
        return r


def _field(v: int, off: int, n: int) -> int:
    return (v >> off) & ((1 << n) - 1)


def _v2_block(src: bytes, pos: int, out: bytearray, limit: int) -> int:
    if pos + 32 > len(src):
        raise LzfseError("truncated v2 header")
    n_raw, p0, p1, p2 = struct.unpack_from("<IQQQ", src, pos + 4)
    n_literals = _field(p0, 0, 20)
    n_lit_payload = _field(p0, 20, 20)
    n_matches = _field(p0, 40, 20)
    literal_bits = _field(p0, 60, 3) - 7
    lit_state = [_field(p1, 0, 10), _field(p1, 10, 10), _field(p1, 20, 10), _field(p1, 30, 10)]
    n_lmd_payload = _field(p1, 40, 20)
    lmd_bits = _field(p1, 60, 3) - 7
    header_size = _field(p2, 0, 32)
    l_state, m_state, d_state = _field(p2, 32, 10), _field(p2, 42, 10), _field(p2, 52, 10)
    if n_literals > LITERALS_PER_BLOCK or n_matches > MATCHES_PER_BLOCK or n_literals % 4:
        raise LzfseError("block counts out of range")
    if max(lit_state) >= LIT_STATES or l_state >= L_STATES or m_state >= M_STATES or d_state >= D_STATES:
        raise LzfseError("initial state out of range")
    if header_size < 32 or pos + header_size > len(src):
        raise LzfseError("bad header size")
    # frequency tables
    freq: list[int] = []
    accum = nbits = 0
    p, hend = pos + 32, pos + header_size
    for _ in range(L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LIT_SYMBOLS):
        while p < hend and nbits + 8 <= 32:
            accum |= src[p] << nbits
            nbits += 8
            p += 1
        b = accum & 31
        n = _FREQ_NBITS[b]
        if n == 8:
            v = 8 + ((accum >> 4) & 0xF)
        elif n == 14:
            v = 24 + ((accum >> 4) & 0x3FF)
        else:
            v = _FREQ_VALUE[b]
        if n > nbits:
            raise LzfseError("frequency table truncated")
        freq.append(v)
        accum >>= n
        nbits -= n
    if nbits >= 8 or p != hend:
        raise LzfseError("frequency table has trailing bits")
    l_freq = freq[:20]
    m_freq = freq[20:40]
    d_freq = freq[40:104]
    lit_freq = freq[104:]
    lit_t = _decoder_table(LIT_STATES, lit_freq)
    l_t = _value_table(L_STATES, l_freq, L_EXTRA, L_BASE)
    m_t = _value_table(M_STATES, m_freq, M_EXTRA, M_BASE)
    d_t = _value_table(D_STATES, d_freq, D_EXTRA, D_BASE)

    # literals
    lstart = hend
    lend = lstart + n_lit_payload
    if lend > len(src):
        raise LzfseError("literal payload truncated")
    bits = _BackBits(src, 0, lend, literal_bits)  # reference checks against src_begin
    lits = bytearray(n_literals)
    s = lit_state
    for i in range(0, n_literals, 4):
        bits.flush()
        for j in range(4):
            k, sym, delta = lit_t[s[j]]
            s[j] = delta + bits.pull(k)
            lits[i + j] = sym
    # lmd
    mstart = lend
    mend = mstart + n_lmd_payload
    if mend > len(src):
        raise LzfseError("lmd payload truncated")
    bits = _BackBits(src, 0, mend, lmd_bits)
    li = 0
    d = -1
    block_start = len(out)
    for _ in range(n_matches):
        bits.flush()
        tb, vb, delta, base = l_t[l_state]
        v = bits.pull(tb)
        l_state = delta + (v >> vb)
        lit_len = base + (v & ((1 << vb) - 1))
        tb, vb, delta, base = m_t[m_state]
        v = bits.pull(tb)
        m_state = delta + (v >> vb)
        match_len = base + (v & ((1 << vb) - 1))
        tb, vb, delta, base = d_t[d_state]
        v = bits.pull(tb)
        d_state = delta + (v >> vb)
        nd = base + (v & ((1 << vb) - 1))
        if nd:
            d = nd
        if li + lit_len > n_literals:
            raise LzfseError("literal overrun")
        out += lits[li:li + lit_len]
        li += lit_len
        if match_len:
            if d <= 0 or d > len(out):
                raise LzfseError("match distance out of range")
            if len(out) + match_len > limit:
                raise LzfseError("output larger than expected")
            start = len(out) - d
            if d >= match_len:
                out += out[start:start + match_len]
            else:
                for k in range(match_len):
                    out.append(out[start + k])
        if len(out) > limit:
            raise LzfseError("output larger than expected")
    if len(out) - block_start != n_raw:
        raise LzfseError(f"block decoded to {len(out) - block_start}, header says {n_raw}")
    return mend


def lzvn_decode(src: bytes, out: bytearray, limit: int, stop_at: int | None = None) -> int:
    """Decode LZVN from ``src`` into ``out``; returns bytes of ``src`` consumed."""
    i, n = 0, len(src)
    d = 0
    target = stop_at if stop_at is not None else limit
    while i < n:
        op = src[i]
        hi = op >> 4
        lit = mlen = 0
        if op == 0x06:  # eos
            return i + 8
        if op in (0x0E, 0x16):
            i += 1
            continue
        if hi == 0xE:
            if op == 0xE0:
                if i + 2 > n:
                    raise LzfseError("lzvn truncated")
                lit = src[i + 1] + 16
                i += 2
            else:
                lit = op & 0xF
                i += 1
        elif hi == 0xF:
            if op == 0xF0:
                if i + 2 > n:
                    raise LzfseError("lzvn truncated")
                mlen = src[i + 1] + 16
                i += 2
            else:
                mlen = op & 0xF
                i += 1
        elif hi in (0xA, 0xB):  # med_d 101LLMMM DDDDDDMM DDDDDDDD
            if i + 3 > n:
                raise LzfseError("lzvn truncated")
            b1, b2 = src[i + 1], src[i + 2]
            lit = (op >> 3) & 3
            mlen = (((op & 7) << 2) | (b1 & 3)) + 3
            d = (b2 << 6) | (b1 >> 2)
            i += 3
        elif hi == 0x7 or hi == 0xD or (op & 7 == 6 and op < 0x40):
            raise LzfseError(f"lzvn undefined opcode {op:#x}")
        else:
            lit = op >> 6
            mlen = ((op >> 3) & 7) + 3
            low = op & 7
            if low == 7:  # lrg_d
                if i + 3 > n:
                    raise LzfseError("lzvn truncated")
                d = src[i + 1] | (src[i + 2] << 8)
                i += 3
            elif low == 6:  # pre_d
                i += 1
            else:  # sml_d
                if i + 2 > n:
                    raise LzfseError("lzvn truncated")
                d = (low << 8) | src[i + 1]
                i += 2
        if lit:
            if i + lit > n:
                raise LzfseError("lzvn literal past end")
            out += src[i:i + lit]
            i += lit
        if mlen:
            if d <= 0 or d > len(out):
                raise LzfseError("lzvn distance out of range")
            start = len(out) - d
            if d >= mlen:
                out += out[start:start + mlen]
            else:
                for k in range(mlen):
                    out.append(out[start + k])
        if len(out) > limit:
            raise LzfseError("lzvn output larger than expected")
        if stop_at is not None and len(out) >= target:
            return i
    raise LzfseError("lzvn stream without end marker")


def decompress(src: bytes, max_out: int) -> bytes:
    out = bytearray()
    pos = 0
    while True:
        if pos + 4 > len(src):
            raise LzfseError("truncated block magic")
        (magic,) = struct.unpack_from("<I", src, pos)
        if magic == ENDOFSTREAM:
            return bytes(out)
        if magic == UNCOMPRESSED:
            (nraw,) = struct.unpack_from("<I", src, pos + 4)
            if pos + 8 + nraw > len(src) or len(out) + nraw > max_out:
                raise LzfseError("bad uncompressed block")
            out += src[pos + 8:pos + 8 + nraw]
            pos += 8 + nraw
        elif magic == V2:
            pos = _v2_block(src, pos, out, max_out)
        elif magic == LZVN:
            nraw, npay = struct.unpack_from("<II", src, pos + 4)
            if pos + 12 + npay > len(src) or len(out) + nraw > max_out:
                raise LzfseError("bad lzvn block")
            before = len(out)
            lzvn_decode(src[pos + 12:pos + 12 + npay], out, before + nraw)
            if len(out) - before != nraw:
                raise LzfseError("lzvn block size mismatch")
            pos += 12 + npay
        elif magic == V1:
            raise LzfseError("bvx1 blocks not implemented in prototype")
        else:
            raise LzfseError(f"bad block magic {magic:#x}")
