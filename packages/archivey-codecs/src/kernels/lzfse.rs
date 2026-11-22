//! LZFSE and raw LZVN decoders: a line-by-line port of archivey's
//! `internal/streams/codecs/lzfse_decoder.py`. Every check and every error message
//! matches the Python one, so the two are interchangeable; the module docstring there
//! lists the checks archivey adds to Apple's reference decoder.
//!
//! Allocation: the output never grows past the caller's limit (each block's declared
//! size is checked against it before the block is decoded), and the only other buffer
//! is one block's literals, at most `n_raw + 3` and at most 40,000 bytes.

use crate::kernels::error::{corrupt, truncated, Result};

const END: &[u8] = b"bvx$";
const STORED: &[u8] = b"bvx-";
const LZVN: &[u8] = b"bvxn";
const V1: &[u8] = b"bvx1";
const V2: &[u8] = b"bvx2";

const L_SYMBOLS: usize = 20;
const M_SYMBOLS: usize = 20;
const D_SYMBOLS: usize = 64;
const LIT_SYMBOLS: usize = 256;
const L_STATES: usize = 64;
const M_STATES: usize = 64;
const D_STATES: usize = 256;
const LIT_STATES: usize = 1024;
const MATCHES_PER_BLOCK: u64 = 10000;
const LITERALS_PER_BLOCK: u64 = 4 * MATCHES_PER_BLOCK;
const SYMBOLS: usize = L_SYMBOLS + M_SYMBOLS + D_SYMBOLS + LIT_SYMBOLS;

const L_EXTRA: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 5, 8];
const L_BASE: [u32; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 28, 60,
];
const M_EXTRA: [u8; 20] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 5, 8, 11];
const M_BASE: [u32; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 24, 56, 312,
];
const D_EXTRA: [u8; 64] = {
    let mut t = [0u8; 64];
    let mut i = 4;
    while i < 64 {
        t[i] = 1 + ((i - 4) / 4) as u8;
        i += 1;
    }
    t
};
const D_BASE: [u32; 64] = [
    0, 1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24, 28, 36, 44, 52, 60, 76, 92, 108, 124, 156, 188, 220,
    252, 316, 380, 444, 508, 636, 764, 892, 1020, 1276, 1532, 1788, 2044, 2556, 3068, 3580, 4092,
    5116, 6140, 7164, 8188, 10236, 12284, 14332, 16380, 20476, 24572, 28668, 32764, 40956, 49148,
    57340, 65532, 81916, 98300, 114684, 131068, 163836, 196604, 229372,
];

// The v2 frequency code: the low 5 bits of the accumulator give the code's length and,
// for lengths up to 5, its value; 8- and 14-bit codes carry 4 and 10 value bits.
const FREQ_NBITS: [u32; 32] = [
    2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2, 14, 2, 3, 2, 5, 2, 3, 2, 8, 2, 3, 2, 5, 2, 3, 2,
    14,
];
const FREQ_VALUE: [u16; 32] = [
    0, 2, 1, 4, 0, 3, 1, 0, 0, 2, 1, 5, 0, 3, 1, 0, 0, 2, 1, 6, 0, 3, 1, 0, 0, 2, 1, 7, 0, 3, 1, 0,
];

const V1_SIZE: usize = 772; // sizeof(lzfse_compressed_block_header_v1), padded
const V2_FIXED: usize = 28; // after the magic: n_raw and three packed words

fn too_long<T>(max_length: u64) -> Result<T> {
    corrupt(format!(
        "LZFSE data decodes to more than {max_length} bytes"
    ))
}

/// `repr()` of a Python `bytes` object, for the unknown-magic message.
fn bytes_repr(b: &[u8]) -> String {
    let quote = if b.contains(&b'\'') && !b.contains(&b'"') {
        '"'
    } else {
        '\''
    };
    let mut s = String::from("b");
    s.push(quote);
    for &c in b {
        match c {
            b'\\' => s.push_str("\\\\"),
            b'\t' => s.push_str("\\t"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            _ if c as char == quote => {
                s.push('\\');
                s.push(quote);
            }
            0x20..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\x{c:02x}")),
        }
    }
    s.push(quote);
    s
}

fn u32_at(src: &[u8], at: usize) -> u64 {
    u32::from_le_bytes(src[at..at + 4].try_into().unwrap()) as u64
}

fn u16_at(src: &[u8], at: usize) -> u64 {
    u16::from_le_bytes(src[at..at + 2].try_into().unwrap()) as u64
}

fn u64_at(src: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(src[at..at + 8].try_into().unwrap())
}

/// The little-endian value of `src[at..at + n]`, `n <= 8`.
fn le_bytes(src: &[u8], at: usize, n: usize) -> u64 {
    let mut v = 0u64;
    for (k, &b) in src[at..at + n].iter().enumerate() {
        v |= (b as u64) << (8 * k);
    }
    v
}

/// Make room for `n` more bytes without letting the capacity pass `limit`. Every call
/// site has already checked that `out.len() + n <= limit`.
fn room(out: &mut Vec<u8>, n: usize, limit: usize) {
    let need = out.len() + n;
    if need > out.capacity() {
        let want = out.capacity().saturating_mul(2).max(need).min(limit);
        out.reserve_exact(want - out.len());
    }
}

/// Append `mlen` bytes copied from `d` bytes back (`1 <= d <= out.len()`), byte by
/// byte in effect: a match may overlap its own output.
fn copy_match(out: &mut Vec<u8>, d: usize, mlen: usize) {
    let start = out.len() - d;
    if d >= mlen {
        out.extend_from_within(start..start + mlen);
        return;
    }
    // The bytes from `start` repeat with period `d`, so every copy of what is already
    // there continues the pattern; each copy doubles the run available.
    let mut left = mlen;
    while left > 0 {
        let n = left.min(out.len() - start);
        out.extend_from_within(start..start + n);
        left -= n;
    }
}

/// Decode a whole LZFSE stream, which must end with `bvx$` and nothing after it, to at
/// most `max_length` bytes.
pub fn lzfse_decompress(src: &[u8], max_length: usize) -> Result<Vec<u8>> {
    let n = src.len();
    let limit = max_length as u64;
    let mut out: Vec<u8> = Vec::new();
    let mut pos = 0usize;
    loop {
        if pos + 4 > n {
            return truncated("LZFSE stream ends before its end-of-stream block");
        }
        let magic = &src[pos..pos + 4];
        if magic == END {
            if pos + 4 != n {
                return corrupt(format!(
                    "{} bytes follow the end of the LZFSE stream",
                    n - pos - 4
                ));
            }
            return Ok(out);
        }
        if magic == STORED {
            if pos + 8 > n {
                return truncated("LZFSE stream ends inside a block header");
            }
            let n_raw = u32_at(src, pos + 4);
            if (pos + 8) as u64 + n_raw > n as u64 {
                return truncated("LZFSE stream ends inside a stored block");
            }
            if out.len() as u64 + n_raw > limit {
                return too_long(limit);
            }
            let n_raw = n_raw as usize;
            room(&mut out, n_raw, max_length);
            out.extend_from_slice(&src[pos + 8..pos + 8 + n_raw]);
            pos += 8 + n_raw;
        } else if magic == LZVN {
            if pos + 12 > n {
                return truncated("LZFSE stream ends inside a block header");
            }
            let n_raw = u32_at(src, pos + 4);
            let n_payload = u32_at(src, pos + 8);
            let start = pos + 12;
            if start as u64 + n_payload > n as u64 {
                return truncated("LZFSE stream ends inside an LZVN block");
            }
            if out.len() as u64 + n_raw > limit {
                return too_long(limit);
            }
            if n_raw == 0 {
                return corrupt("LZVN block declares no output");
            }
            let block_start = out.len();
            let block_limit = block_start + n_raw as usize;
            let payload_end = start + n_payload as usize;
            let end = lzvn(src, start, payload_end, &mut out, block_limit)?;
            if out.len() != block_limit {
                let decoded = out.len() - block_start;
                return corrupt(format!(
                    "LZVN block decodes to {decoded} bytes, its header says {n_raw}"
                ));
            }
            if end != payload_end {
                return corrupt(format!(
                    "{} bytes follow the end of an LZVN block",
                    payload_end - end
                ));
            }
            pos = payload_end;
        } else if magic == V1 || magic == V2 {
            pos = fse_block(src, pos, magic == V2, &mut out, max_length)?;
        } else {
            return corrupt(format!("unknown LZFSE block magic {}", bytes_repr(magic)));
        }
    }
}

/// Decode raw LZVN, as decmpfs types 7 and 8 store it: opcodes up to the
/// end-of-stream opcode, and nothing after it, to at most `max_length` bytes.
pub fn lzvn_decompress(src: &[u8], max_length: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let end = lzvn(src, 0, src.len(), &mut out, max_length)?;
    if end != src.len() {
        return corrupt(format!(
            "{} bytes follow the end of the LZVN data",
            src.len() - end
        ));
    }
    Ok(out)
}

fn undefined<T>(op: u8) -> Result<T> {
    corrupt(format!("undefined LZVN opcode {op:#04x}"))
}

const LZVN_IN_OPCODE: &str = "LZVN data ends inside an opcode";

/// Decode LZVN from `src[i..n]` onto `out` up to its end-of-stream opcode; return the
/// offset just past that opcode. `out` may already hold earlier output, which matches
/// can reach back into, and may not grow past `limit`. `d` starts at 0, which no
/// match may use.
fn lzvn(src: &[u8], mut i: usize, n: usize, out: &mut Vec<u8>, limit: usize) -> Result<usize> {
    let mut d = 0usize;
    loop {
        if i >= n {
            return truncated("LZVN data ends before its end-of-stream opcode");
        }
        let op = src[i];
        let hi = op >> 4;
        let mut lit = 0usize;
        let mut mlen = 0usize;
        if hi < 0xA || hi == 0xC {
            let low = op & 7;
            if low == 6 {
                if op < 0x40 {
                    if op == 0x06 {
                        // end of stream: the opcode and 7 bytes after it
                        if i + 8 > n {
                            return truncated("LZVN data ends inside its end marker");
                        }
                        return Ok(i + 8);
                    }
                    if op == 0x0E || op == 0x16 {
                        // nop
                        i += 1;
                        continue;
                    }
                    return undefined(op);
                }
                if hi == 0x7 {
                    return undefined(op);
                }
                // pre_d: LLMMM110, the previous distance
                lit = (op >> 6) as usize;
                mlen = ((op >> 3) & 7) as usize + 3;
                i += 1;
            } else if hi == 0x7 {
                return undefined(op);
            } else if low == 7 {
                // lrg_d: LLMMM111 DDDDDDDD DDDDDDDD
                if i + 3 > n {
                    return truncated(LZVN_IN_OPCODE);
                }
                lit = (op >> 6) as usize;
                mlen = ((op >> 3) & 7) as usize + 3;
                d = src[i + 1] as usize | (src[i + 2] as usize) << 8;
                i += 3;
            } else {
                // sml_d: LLMMMDDD DDDDDDDD
                if i + 2 > n {
                    return truncated(LZVN_IN_OPCODE);
                }
                lit = (op >> 6) as usize;
                mlen = ((op >> 3) & 7) as usize + 3;
                d = (low as usize) << 8 | src[i + 1] as usize;
                i += 2;
            }
        } else if hi == 0xA || hi == 0xB {
            // med_d: 101LLMMM DDDDDDMM DDDDDDDD
            if i + 3 > n {
                return truncated(LZVN_IN_OPCODE);
            }
            let b1 = src[i + 1] as usize;
            lit = ((op >> 3) & 3) as usize;
            mlen = (((op & 7) as usize) << 2 | (b1 & 3)) + 3;
            d = (src[i + 2] as usize) << 6 | (b1 >> 2);
            i += 3;
        } else if hi == 0xD {
            return undefined(op);
        } else if hi == 0xE {
            // literal only: 1110LLLL, or 11100000 LLLLLLLL
            if op == 0xE0 {
                if i + 2 > n {
                    return truncated(LZVN_IN_OPCODE);
                }
                lit = src[i + 1] as usize + 16;
                i += 2;
            } else {
                lit = (op & 0xF) as usize;
                i += 1;
            }
        } else {
            // match only, previous distance: 1111MMMM, or 11110000 MMMMMMMM
            if op == 0xF0 {
                if i + 2 > n {
                    return truncated(LZVN_IN_OPCODE);
                }
                mlen = src[i + 1] as usize + 16;
                i += 2;
            } else {
                mlen = (op & 0xF) as usize;
                i += 1;
            }
        }
        if lit > 0 {
            if i + lit > n {
                return truncated("LZVN data ends inside a literal");
            }
            if out.len() + lit > limit {
                return too_long(limit as u64);
            }
            room(out, lit, limit);
            out.extend_from_slice(&src[i..i + lit]);
            i += lit;
        }
        if mlen > 0 {
            let size = out.len();
            if d == 0 || d > size {
                return corrupt("LZVN match reaches before the start of the output");
            }
            if size + mlen > limit {
                return too_long(limit as u64);
            }
            room(out, mlen, limit);
            copy_match(out, d, mlen);
        }
    }
}

/// A literal decoder table: per state, `(delta << 16) | (symbol << 8) | k`, as
/// `fse_init_decoder_table` builds it. States no symbol fills stay 0.
fn decoder_table(table: &mut [u32], freq: &[u16], what: &str) -> Result<()> {
    let nstates = table.len();
    let nb = usize::BITS - nstates.leading_zeros();
    let mut total = 0usize;
    let mut s = 0usize;
    for (sym, &f) in freq.iter().enumerate() {
        if f == 0 {
            continue;
        }
        let f = f as usize;
        total += f;
        if total > nstates {
            return corrupt(format!("LZFSE {what} frequencies exceed {nstates} states"));
        }
        let k = nb - (usize::BITS - f.leading_zeros());
        let j0 = ((2 * nstates) >> k) - f;
        for j in 0..f {
            table[s] = if j < j0 {
                let delta = (((f + j) << k) - nstates) as u32;
                delta << 16 | (sym as u32) << 8 | k
            } else {
                let delta = ((j - j0) << (k - 1)) as u32;
                delta << 16 | (sym as u32) << 8 | (k - 1)
            };
            s += 1;
        }
    }
    Ok(())
}

/// One state of a value decoder table, as `fse_init_value_decoder_table` builds it.
#[derive(Clone, Copy, Default)]
struct ValueEntry {
    total_bits: u8,
    value_bits: u8,
    delta: u16,
    base: u32,
}

fn value_table(
    table: &mut [ValueEntry],
    freq: &[u16],
    vbits: &[u8],
    vbase: &[u32],
    what: &str,
) -> Result<()> {
    let nstates = table.len();
    let nb = usize::BITS - nstates.leading_zeros();
    let mut total = 0usize;
    let mut s = 0usize;
    for (sym, &f) in freq.iter().enumerate() {
        if f == 0 {
            continue;
        }
        let f = f as usize;
        total += f;
        if total > nstates {
            return corrupt(format!("LZFSE {what} frequencies exceed {nstates} states"));
        }
        let k = nb - (usize::BITS - f.leading_zeros());
        let j0 = ((2 * nstates) >> k) - f;
        let vb = vbits[sym];
        let base = vbase[sym];
        for j in 0..f {
            table[s] = if j < j0 {
                ValueEntry {
                    total_bits: k as u8 + vb,
                    value_bits: vb,
                    delta: (((f + j) << k) - nstates) as u16,
                    base,
                }
            } else {
                ValueEntry {
                    total_bits: (k - 1) as u8 + vb,
                    value_bits: vb,
                    delta: ((j - j0) << (k - 1)) as u16,
                    base,
                }
            };
            s += 1;
        }
    }
    Ok(())
}

/// The bit stream of an `fse_in_stream` (the 64-bit variant), read backwards; `pos`
/// is the offset of the next byte above the loaded ones.
struct BackBits {
    accum: u64,
    nbits: u32,
    pos: usize,
}

impl BackBits {
    /// `fse_in_checked_init64`: the first load may not pass `start`; the refills may
    /// read back to the start of the input, for the literal and the match streams
    /// alike, as in Apple's decoder.
    fn new(buf: &[u8], start: usize, end: usize, n: i64) -> Result<Self> {
        let width = if n != 0 { 8 } else { 7 };
        if end < start + width {
            return corrupt("LZFSE bit stream is shorter than its first load");
        }
        let at = end - width;
        let accum = le_bytes(buf, at, width);
        let nbits = n + (width as i64) * 8;
        if !(56..64).contains(&nbits) || accum >> (nbits as u32) != 0 {
            return corrupt("LZFSE bit stream starts with bad padding");
        }
        Ok(BackBits {
            accum,
            nbits: nbits as u32,
            pos: at,
        })
    }

    /// `fse_in_checked_flush64`: load whole bytes until at least 56 bits are held.
    #[inline(always)]
    fn refill(&mut self, src: &[u8]) -> Result<()> {
        let take = (63 - self.nbits) & !7;
        if take > 0 {
            let bytes = (take >> 3) as usize;
            if bytes > self.pos {
                return corrupt("LZFSE bit stream reads before the start of the input");
            }
            self.pos -= bytes;
            self.accum = self.accum << take | le_bytes(src, self.pos, bytes);
            self.nbits += take;
        }
        Ok(())
    }

    /// Take the top `k` of the held bits (`k <= nbits`).
    #[inline(always)]
    fn pull(&mut self, k: u32) -> u64 {
        self.nbits -= k;
        let v = self.accum >> self.nbits;
        self.accum &= (1u64 << self.nbits) - 1;
        v
    }
}

/// The 360 frequencies of a `bvx2` header, from `src[p..end]`; none at all (an empty
/// table area) means every frequency is 0, as `lzfse_decode_v1` reads it.
fn v2_frequencies(src: &[u8], mut p: usize, end: usize) -> Result<[u16; SYMBOLS]> {
    let mut freq = [0u16; SYMBOLS];
    if p == end {
        return Ok(freq);
    }
    let mut accum = 0u32;
    let mut nbits = 0u32;
    for f in freq.iter_mut() {
        while p < end && nbits + 8 <= 32 {
            accum |= (src[p] as u32) << nbits;
            nbits += 8;
            p += 1;
        }
        let b = (accum & 31) as usize;
        let width = FREQ_NBITS[b];
        *f = match width {
            8 => 8 + ((accum >> 4) & 0xF) as u16,
            14 => 24 + ((accum >> 4) & 0x3FF) as u16,
            _ => FREQ_VALUE[b],
        };
        if width > nbits {
            return corrupt("LZFSE frequency table ends early");
        }
        accum >>= width;
        nbits -= width;
    }
    if nbits >= 8 || p != end {
        return corrupt("LZFSE frequency table has bytes left over");
    }
    Ok(freq)
}

/// Decode the `bvx1` or `bvx2` block at `pos` onto `out`; return the offset after it.
fn fse_block(
    src: &[u8],
    pos: usize,
    v2: bool,
    out: &mut Vec<u8>,
    max_length: usize,
) -> Result<usize> {
    let n = src.len();
    let n_raw: u64;
    let n_literals: u64;
    let n_matches: u64;
    let n_lit_payload: u64;
    let n_lmd_payload: u64;
    let literal_bits: i64;
    let lmd_bits: i64;
    let lit_state: [u64; 4];
    let l_state0: u64;
    let m_state0: u64;
    let d_state0: u64;
    let header_size: u64;
    let freq: [u16; SYMBOLS];
    if v2 {
        if pos + 4 + V2_FIXED > n {
            return truncated("LZFSE stream ends inside a block header");
        }
        n_raw = u32_at(src, pos + 4);
        let p0 = u64_at(src, pos + 8);
        let p1 = u64_at(src, pos + 16);
        let p2 = u64_at(src, pos + 24);
        n_literals = p0 & 0xFFFFF;
        n_lit_payload = (p0 >> 20) & 0xFFFFF;
        n_matches = (p0 >> 40) & 0xFFFFF;
        literal_bits = ((p0 >> 60) & 7) as i64 - 7;
        lit_state = [
            p1 & 0x3FF,
            (p1 >> 10) & 0x3FF,
            (p1 >> 20) & 0x3FF,
            (p1 >> 30) & 0x3FF,
        ];
        n_lmd_payload = (p1 >> 40) & 0xFFFFF;
        lmd_bits = ((p1 >> 60) & 7) as i64 - 7;
        header_size = p2 & 0xFFFF_FFFF;
        l_state0 = (p2 >> 32) & 0x3FF;
        m_state0 = (p2 >> 42) & 0x3FF;
        d_state0 = (p2 >> 52) & 0x3FF;
        if header_size < (4 + V2_FIXED) as u64 {
            return corrupt(format!("LZFSE block header of {header_size} bytes"));
        }
        if pos as u64 + header_size > n as u64 {
            return truncated("LZFSE stream ends inside a block header");
        }
        freq = v2_frequencies(src, pos + 4 + V2_FIXED, pos + header_size as usize)?;
    } else {
        if pos + V1_SIZE > n {
            return truncated("LZFSE stream ends inside a block header");
        }
        // The fields after the magic: six u32, i32, four u16, i32, three u16, the
        // frequencies (Apple's decoder does not read the second u32, n_payload).
        n_raw = u32_at(src, pos + 4);
        n_literals = u32_at(src, pos + 12);
        n_matches = u32_at(src, pos + 16);
        n_lit_payload = u32_at(src, pos + 20);
        n_lmd_payload = u32_at(src, pos + 24);
        literal_bits = i32::from_le_bytes(src[pos + 28..pos + 32].try_into().unwrap()) as i64;
        lit_state = [
            u16_at(src, pos + 32),
            u16_at(src, pos + 34),
            u16_at(src, pos + 36),
            u16_at(src, pos + 38),
        ];
        lmd_bits = i32::from_le_bytes(src[pos + 40..pos + 44].try_into().unwrap()) as i64;
        l_state0 = u16_at(src, pos + 44);
        m_state0 = u16_at(src, pos + 46);
        d_state0 = u16_at(src, pos + 48);
        let mut f = [0u16; SYMBOLS];
        for (k, v) in f.iter_mut().enumerate() {
            *v = u16_at(src, pos + 50 + 2 * k) as u16;
        }
        freq = f;
        header_size = V1_SIZE as u64;
    }
    if n_literals > LITERALS_PER_BLOCK || n_matches > MATCHES_PER_BLOCK {
        return corrupt("LZFSE block holds more literals or matches than allowed");
    }
    if !n_literals.is_multiple_of(4) {
        return corrupt(format!(
            "LZFSE block literal count {n_literals} is not a multiple of 4"
        ));
    }
    // Every literal a match uses is one output byte, and every match an encoder writes
    // makes at least one, so these tie the block's work to its output.
    if n_literals > n_raw + 3 {
        return corrupt(format!(
            "LZFSE block has {n_literals} literals for {n_raw} bytes of output"
        ));
    }
    if n_matches > n_raw {
        return corrupt(format!(
            "LZFSE block has {n_matches} matches for {n_raw} bytes of output"
        ));
    }
    if lit_state.iter().any(|&s| s >= LIT_STATES as u64)
        || l_state0 >= L_STATES as u64
        || m_state0 >= M_STATES as u64
        || d_state0 >= D_STATES as u64
    {
        return corrupt("LZFSE block starts in a state out of range");
    }
    let lit_end = pos as u64 + header_size + n_lit_payload;
    let lmd_end = lit_end + n_lmd_payload;
    if lmd_end > n as u64 {
        return truncated("LZFSE stream ends inside a block");
    }
    let (lit_end, lmd_end) = (lit_end as usize, lmd_end as usize);
    if out.len() as u64 + n_raw > max_length as u64 {
        return too_long(max_length as u64);
    }

    let mut l_table = [ValueEntry::default(); L_STATES];
    let mut m_table = [ValueEntry::default(); M_STATES];
    let mut d_table = [ValueEntry::default(); D_STATES];
    let mut lit_table = [0u32; LIT_STATES];
    value_table(
        &mut l_table,
        &freq[..20],
        &L_EXTRA,
        &L_BASE,
        "literal length",
    )?;
    value_table(
        &mut m_table,
        &freq[20..40],
        &M_EXTRA,
        &M_BASE,
        "match length",
    )?;
    value_table(&mut d_table, &freq[40..104], &D_EXTRA, &D_BASE, "distance")?;
    decoder_table(&mut lit_table, &freq[104..], "literal")?;

    // Literals: four interleaved states, read backwards from the end of their payload.
    let n_literals = n_literals as usize;
    let mut bits = BackBits::new(src, 0, lit_end, literal_bits)?;
    let mut literals = vec![0u8; n_literals];
    let mut states = [
        lit_state[0] as usize,
        lit_state[1] as usize,
        lit_state[2] as usize,
        lit_state[3] as usize,
    ];
    for chunk in literals.chunks_exact_mut(4) {
        bits.refill(src)?;
        // Four symbols of at most 10 bits each fit in the 56 or more bits just loaded.
        for (slot, s) in chunk.iter_mut().zip(states.iter_mut()) {
            let e = lit_table[*s];
            let v = bits.pull(e & 0xFF);
            *s = (e >> 16) as usize + v as usize;
            *slot = (e >> 8) as u8;
        }
    }

    // Literal length, match length, distance: one triple per match. One refill per
    // triple, as Apple's 64-bit decoder does: it leaves at least 56 bits, and a triple
    // takes at most 14 + 17 + 23 (state bits plus extra bits of each field).
    let mut bits = BackBits::new(src, lit_end, lmd_end, lmd_bits)?;
    let block_start = out.len();
    let block_limit = block_start + n_raw as usize;
    room(out, n_raw as usize, max_length);
    let (mut l_state, mut m_state, mut d_state) =
        (l_state0 as usize, m_state0 as usize, d_state0 as usize);
    let mut used = 0usize;
    // Apple's "illegal previous distance": a first triple must bring its own.
    let mut d: Option<usize> = None;
    for _ in 0..n_matches {
        bits.refill(src)?;
        let e = l_table[l_state];
        let v = bits.pull(e.total_bits as u32);
        l_state = e.delta as usize + (v >> e.value_bits) as usize;
        let lit_len = e.base as usize + (v & ((1u64 << e.value_bits) - 1)) as usize;
        let e = m_table[m_state];
        let v = bits.pull(e.total_bits as u32);
        m_state = e.delta as usize + (v >> e.value_bits) as usize;
        let match_len = e.base as usize + (v & ((1u64 << e.value_bits) - 1)) as usize;
        let e = d_table[d_state];
        let v = bits.pull(e.total_bits as u32);
        d_state = e.delta as usize + (v >> e.value_bits) as usize;
        let new_d = e.base as usize + (v & ((1u64 << e.value_bits) - 1)) as usize;
        if new_d != 0 {
            d = Some(new_d);
        }
        // As lzfse_decode_lmd: every triple's distance must lie within the output once
        // its literals are written, whether or not it has a match.
        let size = out.len();
        let dist = match d {
            Some(dist) if dist <= size + lit_len => dist,
            _ => return corrupt("LZFSE match reaches before the start of the output"),
        };
        if used + lit_len > n_literals {
            return corrupt("LZFSE block uses more literals than it decoded");
        }
        if size + lit_len + match_len > block_limit {
            return corrupt(format!(
                "LZFSE block decodes to more than its {n_raw} bytes"
            ));
        }
        if lit_len > 0 {
            out.extend_from_slice(&literals[used..used + lit_len]);
            used += lit_len;
        }
        if match_len > 0 {
            copy_match(out, dist, match_len);
        }
    }
    if out.len() != block_limit {
        return corrupt(format!(
            "LZFSE block decodes to {} bytes, its header says {n_raw}",
            out.len() - block_start
        ));
    }
    Ok(lmd_end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_repr_matches_python() {
        assert_eq!(bytes_repr(b"abcd"), "b'abcd'");
        assert_eq!(bytes_repr(b"\x00\xff\n\\"), "b'\\x00\\xff\\n\\\\'");
        assert_eq!(bytes_repr(b"a'b\""), "b'a\\'b\"'");
        assert_eq!(bytes_repr(b"a'bc"), "b\"a'bc\"");
    }

    #[test]
    fn overlapping_match_repeats_the_pattern() {
        let mut out = b"xab".to_vec();
        copy_match(&mut out, 2, 7);
        assert_eq!(out, b"xababababa".to_vec());
    }

    #[test]
    fn capacity_stays_within_the_limit() {
        // A literal and a match at distance 1, long matches, then the end marker.
        let mut data = vec![0x40, 0x01, b'a'];
        for _ in 0..200 {
            data.extend_from_slice(&[0xF0, 255 - 16]);
        }
        data.extend_from_slice(&[0x06, 0, 0, 0, 0, 0, 0, 0]);
        let size = 4 + 255 * 200;
        let out = lzvn_decompress(&data, size).unwrap();
        assert_eq!(out.len(), size);
        assert!(out.capacity() <= size, "{} > {size}", out.capacity());
    }
}
