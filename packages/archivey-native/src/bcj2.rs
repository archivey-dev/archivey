//! BCJ2 (7-Zip's four-stream x86 branch converter): a port of the decode loop of
//! archivey's `Bcj2DecoderStream` (`internal/streams/codecs/bcj2_filter.py`). The
//! Python stream keeps seeking, `tell` and the output buffer; this core decodes.
//! Same candidates, same range coder, same refusals and messages.

use crate::error::DecodeError;

const BLOCK: usize = 64 * 1024;
const TOP: u32 = 1 << 24;
const NUM_MOVE_BITS: u32 = 5;
const PROB_INIT: u16 = 1024;
const E9_CONTEXT: usize = 256;
const JCC_CONTEXT: usize = 257;

pub const MAIN: usize = 0;
pub const CALL: usize = 1;
pub const JUMP: usize = 2;
pub const RC: usize = 3;

/// The four input streams. `read(which, n)` returns up to `n` bytes, empty at the end.
pub trait Streams {
    type Error;
    fn read(&mut self, which: usize, n: usize) -> Result<Vec<u8>, Self::Error>;
}

type R<T, E> = Result<T, DecodeError<E>>;

#[derive(Default)]
struct Buffered {
    buf: Vec<u8>,
    pos: usize,
}

impl Buffered {
    fn left(&self) -> usize {
        self.buf.len() - self.pos
    }
}

pub struct Bcj2 {
    main: Vec<u8>,
    mpos: usize,
    call: Buffered,
    jump: Buffered,
    rc: Buffered,
    probs: [u16; 258],
    prev: u8,
    range: u32,
    code: Option<u32>,
    out_pos: u64,
}

impl Default for Bcj2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Bcj2 {
    pub fn new() -> Self {
        Bcj2 {
            main: Vec::new(),
            mpos: 0,
            call: Buffered::default(),
            jump: Buffered::default(),
            rc: Buffered::default(),
            probs: [PROB_INIT; 258],
            prev: 0,
            range: 0xFFFF_FFFF,
            code: None,
            out_pos: 0,
        }
    }

    fn rc_byte<S: Streams>(&mut self, s: &mut S) -> R<u32, S::Error> {
        if self.rc.left() == 0 {
            self.rc.buf = s.read(RC, BLOCK).map_err(DecodeError::Source)?;
            self.rc.pos = 0;
            if self.rc.buf.is_empty() {
                return Err(DecodeError::Truncated("BCJ2 range coder stream ended early".into()));
            }
        }
        let b = self.rc.buf[self.rc.pos];
        self.rc.pos += 1;
        Ok(b as u32)
    }

    fn target<S: Streams>(&mut self, which: usize, s: &mut S) -> R<u32, S::Error> {
        let (t, label) = if which == CALL { (&mut self.call, "call") } else { (&mut self.jump, "jump") };
        if t.left() < 4 {
            let mut data = t.buf[t.pos..].to_vec();
            while data.len() < 4 {
                let chunk = s.read(which, BLOCK).map_err(DecodeError::Source)?;
                if chunk.is_empty() {
                    break;
                }
                data.extend_from_slice(&chunk);
            }
            if data.len() < 4 {
                return Err(DecodeError::Truncated(format!("BCJ2 {label} stream ended early")));
            }
            t.buf = data;
            t.pos = 0;
        }
        let b = &t.buf[t.pos..t.pos + 4];
        t.pos += 4;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Decode to the end of the current `main` block, or until `left` bytes are out,
    /// appending to `out`. On an error, `out` holds what decoded before it.
    pub fn decode_block<S: Streams>(&mut self, left: u64, out: &mut Vec<u8>, s: &mut S) -> R<(), S::Error> {
        let base = self.out_pos;
        let r = self.decode_block_inner(left, out, s);
        self.out_pos = base + out.len() as u64;
        r
    }

    fn decode_block_inner<S: Streams>(&mut self, mut left: u64, out: &mut Vec<u8>, s: &mut S) -> R<(), S::Error> {
        if self.code.is_none() {
            let mut code: u64 = 0;
            for _ in 0..5 {
                code = (code << 8) | self.rc_byte(s)? as u64;
            }
            if code >> 32 != 0 || code == 0xFFFF_FFFF {
                return Err(DecodeError::Corrupt("BCJ2 range coder stream has an invalid start".into()));
            }
            self.code = Some(code as u32);
        }
        if self.mpos == self.main.len() {
            self.main = s.read(MAIN, BLOCK).map_err(DecodeError::Source)?;
            self.mpos = 0;
            if self.main.is_empty() {
                return Err(DecodeError::Truncated("BCJ2 main stream ended early".into()));
            }
        }
        let start = self.out_pos;
        let main = std::mem::take(&mut self.main);
        let end = main.len();
        let mut code = self.code.unwrap();
        let mut rng = self.range;
        let result = (|| -> R<(), S::Error> {
            loop {
                // The next candidate opcode at or after mpos.
                let mpos = self.mpos;
                let mut pos = end;
                let mut i = mpos;
                while i < end {
                    let b = main[i];
                    if b == 0xE8 || b == 0xE9 {
                        pos = i;
                        break;
                    }
                    if b & 0xF0 == 0x80 {
                        let before = if i == mpos { self.prev } else { main[i - 1] };
                        if before == 0x0F {
                            pos = i;
                            break;
                        }
                    }
                    i += 1;
                }
                if pos == end {
                    let take = ((end - mpos) as u64).min(left) as usize;
                    if take > 0 {
                        out.extend_from_slice(&main[mpos..mpos + take]);
                        left -= take as u64;
                        self.mpos = mpos + take;
                        self.prev = main[mpos + take - 1];
                    }
                    return Ok(());
                }
                let copied = (pos + 1 - mpos) as u64;
                if copied >= left {
                    let take = left as usize;
                    out.extend_from_slice(&main[mpos..mpos + take]);
                    self.mpos = mpos + take;
                    return Ok(());
                }
                let b = main[pos];
                let context = if b == 0xE8 {
                    (if pos != mpos { main[pos - 1] } else { self.prev }) as usize
                } else if b == 0xE9 {
                    E9_CONTEXT
                } else {
                    JCC_CONTEXT
                };
                out.extend_from_slice(&main[mpos..pos + 1]);
                left -= copied;
                self.mpos = pos + 1;

                if rng < TOP {
                    rng <<= 8;
                    code = (code << 8) | self.rc_byte(s)?;
                }
                let p = self.probs[context] as u32;
                let bound = (rng >> 11) * p;
                if code < bound {
                    rng = bound;
                    self.probs[context] = (p + ((2048 - p) >> NUM_MOVE_BITS)) as u16;
                    self.prev = b;
                    continue;
                }
                rng -= bound;
                code -= bound;
                self.probs[context] = (p - (p >> NUM_MOVE_BITS)) as u16;

                let target = self.target(if b == 0xE8 { CALL } else { JUMP }, s)?;
                let here = start + out.len() as u64 + 4;
                let dest = target.wrapping_sub(here as u32);
                let bytes = dest.to_le_bytes();
                if left <= 4 {
                    out.extend_from_slice(&bytes[..left as usize]);
                    return Ok(());
                }
                out.extend_from_slice(&bytes);
                left -= 4;
                self.prev = (dest >> 24) as u8;
            }
        })();
        self.main = main;
        self.range = rng;
        self.code = Some(code);
        result
    }

    /// Refuse bytes left in `main`, `call` or `jump` after the last output byte.
    pub fn check_inputs_finished<S: Streams>(&mut self, s: &mut S) -> R<(), S::Error> {
        if self.mpos < self.main.len() || !s.read(MAIN, 1).map_err(DecodeError::Source)?.is_empty() {
            return Err(DecodeError::Corrupt("BCJ2 main stream has bytes past the end of the output".into()));
        }
        for (which, label) in [(CALL, "call"), (JUMP, "jump")] {
            let t = if which == CALL { &self.call } else { &self.jump };
            let more = t.left() > 0 || !s.read(which, 1).map_err(DecodeError::Source)?.is_empty();
            if more {
                return Err(DecodeError::Corrupt(format!("BCJ2 {label} stream has bytes past the end of the output")));
            }
        }
        Ok(())
    }
}
