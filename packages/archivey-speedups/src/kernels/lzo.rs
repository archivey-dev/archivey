//! LZO1X block decoder: a line-by-line port of archivey's
//! `lzo1x_decompress_python` (`internal/streams/codecs/lzo_decoder.py`). Every error
//! message matches the Python one, so the two are interchangeable.

use crate::kernels::error::{corrupt, Result};

fn too_big<T>(limit: usize) -> Result<T> {
    corrupt(format!("the data decodes to more than {limit} bytes"))
}

const END_INSTR: &str = "the input ends inside an instruction";
const PAST_END: &str = "a literal run passes the end of the input";

/// Make room for `n` more bytes without letting the capacity pass `limit`. Every call
/// site has already checked that `out.len() + n <= limit`; the doubling keeps appends
/// amortised, and the clamp keeps `limit` the bound on the allocation, not only on
/// the length (a plain `extend` could double past it).
fn room(out: &mut Vec<u8>, n: usize, limit: usize) {
    let need = out.len() + n;
    if need > out.capacity() {
        let want = out.capacity().saturating_mul(2).max(need).min(limit);
        out.reserve_exact(want - out.len());
    }
}

pub fn lzo1x_decompress(data: &[u8], limit: usize) -> Result<Vec<u8>> {
    let end = data.len();
    let mut out: Vec<u8> = Vec::with_capacity(limit.min(end.saturating_mul(4)).min(1 << 26));
    let mut ip = 0usize;
    let mut state = 0usize;
    if end > 0 && data[0] > 17 {
        let t = (data[0] - 17) as usize;
        ip = 1;
        if ip + t > end {
            return corrupt(PAST_END);
        }
        if t > limit {
            return too_big(limit);
        }
        room(&mut out, t, limit);
        out.extend_from_slice(&data[ip..ip + t]);
        ip += t;
        state = if t > 3 { 4 } else { t };
    }
    loop {
        if ip >= end {
            return corrupt(END_INSTR);
        }
        let t = data[ip] as usize;
        ip += 1;
        let distance: usize;
        let length: usize;
        let nxt: usize;
        if t < 16 {
            if state == 0 {
                let mut t = t;
                if t == 0 {
                    let zeros = ip;
                    while ip < end && data[ip] == 0 {
                        ip += 1;
                    }
                    if ip >= end {
                        return corrupt(END_INSTR);
                    }
                    t = (ip - zeros) * 255 + 15 + data[ip] as usize;
                    ip += 1;
                }
                let count = t + 3;
                if ip + count > end {
                    return corrupt(PAST_END);
                }
                if out.len() + count > limit {
                    return too_big(limit);
                }
                room(&mut out, count, limit);
                out.extend_from_slice(&data[ip..ip + count]);
                ip += count;
                state = 4;
                continue;
            }
            if ip >= end {
                return corrupt(END_INSTR);
            }
            if state != 4 {
                distance = 1 + (t >> 2) + ((data[ip] as usize) << 2);
                length = 2;
            } else {
                distance = 0x801 + (t >> 2) + ((data[ip] as usize) << 2);
                length = 3;
            }
            ip += 1;
            nxt = t & 3;
        } else if t >= 64 {
            if ip >= end {
                return corrupt(END_INSTR);
            }
            distance = 1 + ((t >> 2) & 7) + ((data[ip] as usize) << 3);
            ip += 1;
            length = (t >> 5) + 1;
            nxt = t & 3;
        } else {
            let (mut len, base) = if t >= 32 { (t & 31, 31) } else { (t & 7, 7) };
            if len == 0 {
                let zeros = ip;
                while ip < end && data[ip] == 0 {
                    ip += 1;
                }
                if ip >= end {
                    return corrupt(END_INSTR);
                }
                len = (ip - zeros) * 255 + base + data[ip] as usize;
                ip += 1;
            }
            length = len + 2;
            if ip + 2 > end {
                return corrupt(END_INSTR);
            }
            let field = data[ip] as usize | (data[ip + 1] as usize) << 8;
            ip += 2;
            nxt = field & 3;
            if t >= 32 {
                distance = 1 + (field >> 2);
            } else {
                let d = ((t & 8) << 11) + (field >> 2);
                if d == 0 {
                    // The end marker: every writer puts 17, 0, 0, a length of 3. The
                    // kernel's decoder and compress-utils refuse any other length, and
                    // so does this, as the Python twin; liblzo2 takes any.
                    if length != 3 {
                        return corrupt(format!("the end marker has a length of {length}, not 3"));
                    }
                    if ip != end {
                        return corrupt(format!("{} bytes follow the end marker", end - ip));
                    }
                    return Ok(out);
                }
                distance = d + 0x4000;
            }
        }
        if distance > out.len() {
            return corrupt("a match refers to bytes before the start of the output");
        }
        let start = out.len() - distance;
        if out.len() + length > limit {
            return too_big(limit);
        }
        room(&mut out, length, limit);
        if distance >= length {
            out.extend_from_within(start..start + length);
        } else {
            // Overlapping: repeat the last `distance` bytes.
            for k in 0..length {
                let b = out[start + k];
                out.push(b);
            }
        }
        if nxt > 0 {
            if ip + nxt > end {
                return corrupt(PAST_END);
            }
            if out.len() + nxt > limit {
                return too_big(limit);
            }
            room(&mut out, nxt, limit);
            out.extend_from_slice(&data[ip..ip + nxt]);
            ip += nxt;
        }
        state = nxt;
    }
}

#[cfg(test)]
mod tests {
    use super::lzo1x_decompress;

    #[test]
    fn capacity_stays_within_the_limit() {
        // One literal, then many 33-byte matches at distance 1, then the end marker:
        // the output is far larger than the reservation made from the input size.
        for n in [1usize, 7, 100, 1000, 4097] {
            let mut data = vec![18, b'a'];
            for _ in 0..n {
                data.extend_from_slice(&[63, 0, 0]);
            }
            data.extend_from_slice(&[17, 0, 0]);
            let size = 1 + 33 * n;
            let out = lzo1x_decompress(&data, size).unwrap();
            assert_eq!(out, vec![b'a'; size]);
            assert!(out.capacity() <= size, "{} > {size}", out.capacity());
        }
    }
}
