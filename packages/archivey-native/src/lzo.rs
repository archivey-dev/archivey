//! LZO1X block decoder: a line-by-line port of archivey's
//! `lzo1x_decompress_python` (`internal/streams/codecs/lzo_decoder.py`). Every error
//! message matches the Python one, so the two are interchangeable.

use crate::error::{corrupt, Result};

fn too_big<T>(limit: usize) -> Result<T> {
    corrupt(format!("the data decodes to more than {limit} bytes"))
}

const END_INSTR: &str = "the input ends inside an instruction";
const PAST_END: &str = "a literal run passes the end of the input";

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
            out.extend_from_slice(&data[ip..ip + nxt]);
            ip += nxt;
        }
        state = nxt;
    }
}
