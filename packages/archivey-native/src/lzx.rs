//! LZX as Microsoft cabinets store it: a port of archivey's `LzxDecoder`
//! (`internal/streams/codecs/lzx_decoder.py`), which follows libmspack's `lzxd.c`.
//! Same state machine, same checks, same messages. Where the Python decoder relies on
//! Python semantics (a slice assignment that would grow the window, an `IndexError`),
//! this port raises a `Corrupt` error instead; see the parity notes in the report.

use crate::error::{DecodeError, Result};

pub const FRAME_SIZE: usize = 32768;
pub const MIN_WINDOW_BITS: u32 = 15;
pub const MAX_WINDOW_BITS: u32 = 21;

const NUM_CHARS: usize = 256;
const PRETREE_SYMBOLS: usize = 20;
const ALIGNED_SYMBOLS: usize = 8;
const LENGTH_SYMBOLS: usize = 249;
const PRIMARY_LENGTHS: usize = 7;
const MIN_MATCH: usize = 2;
const MAIN_MAX: usize = NUM_CHARS + 290 * 8;
const LENGTH_MAX: usize = LENGTH_SYMBOLS + 1;
const RUN_SLACK: usize = 64;

const VERBATIM: u32 = 1;
const ALIGNED: u32 = 2;
const UNCOMPRESSED: u32 = 3;

const POSITION_SLOTS: [usize; 7] = [30, 32, 34, 36, 38, 42, 50];
// The full Python table, indexed by window_bits - 15, has 11 entries; only 7 are
// reachable (window bits 15..21).

const PADDING_ALLOWED: usize = 2;
const MAX_PADDING: usize = 8;
const MAX_CODE: u32 = 16;
const ROOT_BITS: u32 = 10;

const fn extra_bits_table() -> [u32; 290] {
    let mut t = [0u32; 290];
    let mut s = 0;
    while s < 290 {
        t[s] = if s < 4 {
            0
        } else {
            let e = s / 2 - 1;
            if e < 17 { e as u32 } else { 17 }
        };
        s += 1;
    }
    t
}

const fn position_base_table() -> [u32; 290] {
    let eb = extra_bits_table();
    let mut t = [0u32; 290];
    let mut s = 1;
    while s < 290 {
        t[s] = t[s - 1] + (1 << eb[s - 1]);
        s += 1;
    }
    t
}

static EXTRA_BITS: [u32; 290] = extra_bits_table();
static POSITION_BASE: [u32; 290] = position_base_table();

/// A two-level decoding table, as in the Python decoder: a root entry
/// `symbol << 5 | length`, or `!(start << 5 | bits)` pointing to a sub-table.
#[derive(Clone)]
struct Tree {
    table: Vec<i32>,
    root: u32,
}

fn corrupt<T, E>(msg: impl Into<String>) -> Result<T, E> {
    Err(DecodeError::Corrupt(msg.into()))
}

fn build_table<E>(lengths: &[u8], count: usize, what: &str) -> Result<Option<Tree>, E> {
    let mut by_length: [Vec<usize>; (MAX_CODE + 1) as usize] = Default::default();
    for (symbol, &len) in lengths[..count].iter().enumerate() {
        if len != 0 {
            by_length[len as usize].push(symbol);
        }
    }
    let longest = (1..=MAX_CODE as usize).rev().find(|&n| !by_length[n].is_empty()).unwrap_or(0);
    if longest == 0 {
        return Ok(None);
    }
    let root = (longest as u32).min(ROOT_BITS);
    let full: u64 = 1 << MAX_CODE;
    let shift = MAX_CODE - root;
    let mut pos: u64 = 0;
    let mut table = vec![0i32; 1 << root];
    let mut long_codes: Vec<(u64, u32, usize)> = Vec::new();
    for length in 1..=longest as u32 {
        let span: u64 = 1 << (MAX_CODE - length);
        let symbols = &by_length[length as usize];
        if pos + span * symbols.len() as u64 > full {
            return corrupt(format!("LZX {what} tree overfills its code space"));
        }
        if length <= root {
            let fill = 1usize << (root - length);
            for &symbol in symbols {
                let at = (pos >> shift) as usize;
                let v = ((symbol as i32) << 5) | length as i32;
                table[at..at + fill].fill(v);
                pos += span;
            }
        } else {
            for &symbol in symbols {
                long_codes.push((pos, length, symbol));
                pos += span;
            }
        }
    }
    if pos != full {
        return corrupt(format!("LZX {what} tree does not fill its code space"));
    }
    let low: u64 = (1 << shift) - 1;
    let mut i = 0;
    while i < long_codes.len() {
        let prefix = long_codes[i].0 >> shift;
        let mut j = i;
        while j + 1 < long_codes.len() && long_codes[j + 1].0 >> shift == prefix {
            j += 1;
        }
        let bits = long_codes[j].1 - root;
        let start = table.len();
        table.resize(start + (1 << bits), 0);
        table[prefix as usize] = !(((start as i32) << 5) | bits as i32);
        for &(code_pos, length, symbol) in &long_codes[i..=j] {
            let at = start + ((code_pos & low) >> (shift - bits)) as usize;
            let fill = 1usize << (root + bits - length);
            let v = ((symbol as i32) << 5) | (length - root) as i32;
            table[at..at + fill].fill(v);
        }
        i = j + 1;
    }
    Ok(Some(Tree { table, root }))
}

/// Where the decoder gets its input: a cabinet's data blocks, one run at a time.
pub trait Input {
    type Error;
    /// The next run of input bytes, or `None` at the end of the input.
    fn more(&mut self) -> std::result::Result<Option<Vec<u8>>, Self::Error>;
}

pub struct LzxDecoder {
    window_size: usize,
    window: Vec<u8>,
    main_symbols: usize,
    buf: Vec<u8>,
    pos: usize,
    bits: u64,
    nbits: u32,
    padding: usize,
    main_lengths: Vec<u8>,
    length_lengths: Vec<u8>,
    main_table: Option<Tree>,
    length_table: Option<Tree>,
    aligned_table: Option<Tree>,
    r0: u64,
    r1: u64,
    r2: u64,
    header_read: bool,
    intel_size: u32,
    intel_started: bool,
    block_type: u32,
    block_length: usize,
    block_remaining: usize,
    window_pos: usize,
    offset: u64,
    frame: u64,
}

#[inline(always)]
fn mask(n: u32) -> u64 {
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}

impl LzxDecoder {
    pub fn new(window_bits: u32) -> Result<Self> {
        if !(MIN_WINDOW_BITS..=MAX_WINDOW_BITS).contains(&window_bits) {
            return corrupt(format!("LZX window of 2**{window_bits} bytes"));
        }
        let window_size = 1usize << window_bits;
        Ok(LzxDecoder {
            window_size,
            window: vec![0; window_size],
            main_symbols: NUM_CHARS + (POSITION_SLOTS[(window_bits - 15) as usize] << 3),
            buf: Vec::new(),
            pos: 0,
            bits: 0,
            nbits: 0,
            padding: 0,
            main_lengths: vec![0; MAIN_MAX + RUN_SLACK],
            length_lengths: vec![0; LENGTH_MAX + RUN_SLACK],
            main_table: None,
            length_table: None,
            aligned_table: None,
            r0: 1,
            r1: 1,
            r2: 1,
            header_read: false,
            intel_size: 0,
            intel_started: false,
            block_type: 0,
            block_length: 0,
            block_remaining: 0,
            window_pos: 0,
            offset: 0,
            frame: 0,
        })
    }

    // ── Input ───────────────────────────────────────────────────────────────────

    fn refill<I: Input>(&mut self, need: u32, input: &mut I) -> Result<(), I::Error> {
        while self.nbits < need {
            if self.pos + 2 > self.buf.len() {
                self.input_more(input)?;
            }
            let word = (self.buf[self.pos + 1] as u64) << 8 | self.buf[self.pos] as u64;
            self.bits = ((self.bits & mask(self.nbits)) << 16) | word;
            self.pos += 2;
            self.nbits += 16;
        }
        Ok(())
    }

    fn input_more<I: Input>(&mut self, input: &mut I) -> Result<(), I::Error> {
        let keep = self.pos.min(8);
        self.buf.drain(..self.pos - keep);
        self.pos = keep;
        while self.buf.len() - self.pos < 2 {
            let data = if self.padding > 0 { None } else { input.more().map_err(DecodeError::Source)? };
            match data {
                Some(d) => self.buf.extend_from_slice(&d),
                None => {
                    if self.padding >= MAX_PADDING {
                        return Err(DecodeError::Truncated("LZX stream ends before its output".into()));
                    }
                    self.padding += 2;
                    self.buf.extend_from_slice(&[0, 0]);
                }
            }
        }
        Ok(())
    }

    fn check_overread<E>(&self) -> Result<(), E> {
        if self.padding == 0 {
            return Ok(());
        }
        let unread = (self.buf.len() - self.pos) * 8 + self.nbits as usize;
        if (self.padding * 8) as i64 - unread as i64 > (PADDING_ALLOWED * 8) as i64 {
            return Err(DecodeError::Truncated("LZX stream ends before its output".into()));
        }
        Ok(())
    }

    fn read_bits<I: Input>(&mut self, n: u32, input: &mut I) -> Result<u32, I::Error> {
        if self.nbits < n {
            self.refill(n, input)?;
        }
        self.nbits -= n;
        Ok(((self.bits >> self.nbits) & mask(n)) as u32)
    }

    fn raw_bytes<I: Input>(&mut self, n: usize, input: &mut I) -> Result<std::ops::Range<usize>, I::Error> {
        debug_assert_eq!(self.nbits, 0);
        while self.buf.len() - self.pos < n {
            let data = if self.padding > 0 { None } else { input.more().map_err(DecodeError::Source)? };
            let Some(d) = data else {
                return Err(DecodeError::Truncated("LZX stream ends inside an uncompressed block".into()));
            };
            let keep = self.pos.min(8);
            self.buf.drain(..self.pos - keep);
            self.pos = keep;
            self.buf.extend_from_slice(&d);
        }
        let at = self.pos;
        self.pos += n;
        Ok(at..at + n)
    }

    fn align_for_raw<I: Input>(&mut self, input: &mut I) -> Result<(), I::Error> {
        let drop = match self.nbits % 16 { 0 => 16, d => d };
        if self.nbits < drop {
            self.refill(drop, input)?;
        }
        self.nbits -= drop;
        self.pos -= (self.nbits / 8) as usize;
        self.bits = 0;
        self.nbits = 0;
        Ok(())
    }

    // ── Trees ───────────────────────────────────────────────────────────────────

    fn read_pre_symbol<I: Input>(&mut self, pre: &Option<Tree>, input: &mut I) -> Result<usize, I::Error> {
        let Some(tree) = pre else {
            return corrupt("LZX pretree symbol read from an empty tree");
        };
        if self.nbits < MAX_CODE {
            self.refill(MAX_CODE, input)?;
        }
        let (bits, mut nbits) = (self.bits, self.nbits);
        let root = tree.root;
        let mut entry = tree.table[((bits >> (nbits - root)) & mask(root)) as usize];
        if entry < 0 {
            nbits -= root;
            entry = !entry;
            let sub = (entry & 31) as u32;
            entry = tree.table[(entry >> 5) as usize + ((bits >> (nbits - sub)) & mask(sub)) as usize];
        }
        self.nbits = nbits - (entry & 31) as u32;
        Ok((entry >> 5) as usize)
    }

    fn read_lengths<I: Input>(&mut self, main: bool, first: usize, last: usize, input: &mut I) -> Result<(), I::Error> {
        let mut pre = [0u8; PRETREE_SYMBOLS];
        for p in pre.iter_mut() {
            *p = self.read_bits(4, input)? as u8;
        }
        let table = build_table(&pre, PRETREE_SYMBOLS, "pretree")?;
        let mut x = first;
        while x < last {
            let code = self.read_pre_symbol(&table, input)?;
            if code == 17 {
                let run = self.read_bits(4, input)? as usize + 4;
                self.lengths(main)[x..x + run].fill(0);
                x += run;
            } else if code == 18 {
                let run = self.read_bits(5, input)? as usize + 20;
                self.lengths(main)[x..x + run].fill(0);
                x += run;
            } else if code == 19 {
                let run = self.read_bits(1, input)? as usize + 4;
                let code = self.read_pre_symbol(&table, input)?;
                let lengths = self.lengths(main);
                let value = (lengths[x] as i32 - code as i32).rem_euclid(17) as u8;
                lengths[x..x + run].fill(value);
                x += run;
            } else {
                let lengths = self.lengths(main);
                lengths[x] = (lengths[x] as i32 - code as i32).rem_euclid(17) as u8;
                x += 1;
            }
        }
        Ok(())
    }

    fn lengths(&mut self, main: bool) -> &mut Vec<u8> {
        if main { &mut self.main_lengths } else { &mut self.length_lengths }
    }

    fn read_block_header<I: Input>(&mut self, input: &mut I) -> Result<(), I::Error> {
        if self.block_type == UNCOMPRESSED && self.block_length & 1 == 1 {
            self.raw_bytes(1, input)?;
        }
        let block_type = self.read_bits(3, input)?;
        let high = self.read_bits(16, input)? as usize;
        let length = (high << 8) | self.read_bits(8, input)? as usize;
        self.block_type = block_type;
        self.block_length = length;
        self.block_remaining = length;
        if block_type == ALIGNED {
            let mut aligned = [0u8; ALIGNED_SYMBOLS];
            for a in aligned.iter_mut() {
                *a = self.read_bits(3, input)? as u8;
            }
            self.aligned_table = build_table(&aligned, ALIGNED_SYMBOLS, "aligned")?;
        }
        if block_type == VERBATIM || block_type == ALIGNED {
            self.read_lengths(true, 0, NUM_CHARS, input)?;
            let ms = self.main_symbols;
            self.read_lengths(true, NUM_CHARS, ms, input)?;
            self.main_table = build_table(&self.main_lengths, MAIN_MAX, "main")?;
            if self.main_lengths[0xE8] != 0 {
                self.intel_started = true;
            }
            self.read_lengths(false, 0, LENGTH_SYMBOLS, input)?;
            self.length_table = build_table(&self.length_lengths, LENGTH_MAX, "length")?;
        } else if block_type == UNCOMPRESSED {
            self.intel_started = true;
            self.align_for_raw(input)?;
            let r = self.raw_bytes(12, input)?;
            let s = &self.buf[r];
            self.r0 = u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64;
            self.r1 = u32::from_le_bytes([s[4], s[5], s[6], s[7]]) as u64;
            self.r2 = u32::from_le_bytes([s[8], s[9], s[10], s[11]]) as u64;
        } else {
            return corrupt(format!("LZX block type {block_type}"));
        }
        Ok(())
    }

    // ── Frames ──────────────────────────────────────────────────────────────────

    pub fn decode_frame<I: Input>(&mut self, frame_size: usize, input: &mut I) -> Result<Vec<u8>, I::Error> {
        if !(frame_size > 0 && frame_size <= FRAME_SIZE) {
            return Err(DecodeError::Value(format!("frame size {frame_size}")));
        }
        if !self.header_read {
            if self.read_bits(1, input)? != 0 {
                let high = self.read_bits(16, input)?;
                self.intel_size = (high << 16) | self.read_bits(16, input)?;
            }
            self.header_read = true;
        }
        let frame_start = self.window_pos;
        let mut todo = frame_size;
        while todo > 0 {
            if self.block_remaining == 0 {
                self.read_block_header(input)?;
            }
            let run = self.block_remaining.min(todo);
            let done = if self.block_type == UNCOMPRESSED {
                let pos = self.window_pos;
                if pos + run > self.window_size {
                    return corrupt("LZX match runs past the end of the window");
                }
                let r = self.raw_bytes(run, input)?;
                self.window[pos..pos + run].copy_from_slice(&self.buf[r]);
                self.window_pos = pos + run;
                run
            } else {
                self.decode_run(run, input)?
            };
            if done > self.block_remaining {
                return corrupt("LZX match runs past the end of its block");
            }
            self.block_remaining -= done;
            todo = todo.saturating_sub(done);
        }
        if self.window_pos - frame_start != frame_size {
            return corrupt("LZX match runs past the end of a frame");
        }
        self.nbits -= self.nbits % 16;
        self.check_overread()?;
        let mut out = self.window[frame_start..self.window_pos].to_vec();
        if self.intel_started && self.intel_size != 0 && self.frame < 32768 {
            self.undo_e8(&mut out);
        }
        self.offset += frame_size as u64;
        self.frame += 1;
        if self.window_pos == self.window_size {
            self.window_pos = 0;
        }
        Ok(out)
    }

    fn decode_run<I: Input>(&mut self, run: usize, input: &mut I) -> Result<usize, I::Error> {
        if self.main_table.is_none() {
            return corrupt("LZX main symbol read from an empty tree");
        }
        // Take the trees out so the hot loop can borrow `self` mutably.
        let main = self.main_table.take().unwrap();
        let length = self.length_table.take();
        let aligned = self.aligned_table.take();
        let r = self.decode_run_inner(run, &main, length.as_ref(), aligned.as_ref(), input);
        self.main_table = Some(main);
        self.length_table = length;
        self.aligned_table = aligned;
        r
    }

    #[inline(always)]
    fn lookup(tree: &Tree, bits: u64, nbits: &mut u32) -> i32 {
        let root = tree.root;
        let mut entry = tree.table[((bits >> (*nbits - root)) & mask(root)) as usize];
        if entry < 0 {
            *nbits -= root;
            entry = !entry;
            let sub = (entry & 31) as u32;
            entry = tree.table[(entry >> 5) as usize + ((bits >> (*nbits - sub)) & mask(sub)) as usize];
        }
        *nbits -= (entry & 31) as u32;
        entry >> 5
    }

    fn slow_fill<I: Input>(&mut self, bits: &mut u64, nbits: &mut u32, input: &mut I) -> Result<(), I::Error> {
        self.bits = *bits;
        self.nbits = *nbits;
        self.refill(32, input)?;
        *bits = self.bits;
        *nbits = self.nbits;
        Ok(())
    }

    fn decode_run_inner<I: Input>(
        &mut self,
        run: usize,
        main: &Tree,
        length_tree: Option<&Tree>,
        aligned_tree: Option<&Tree>,
        input: &mut I,
    ) -> Result<usize, I::Error> {
        let is_aligned = self.block_type == ALIGNED;
        let window_size = self.window_size;
        let decoded = self.offset;
        let (mut r0, mut r1, mut r2) = (self.r0, self.r1, self.r2);
        let start = self.window_pos;
        let mut pos = start;
        let end = pos + run;
        let mut bits = self.bits;
        let mut nbits = self.nbits;
        let result: Result<(), I::Error> = (|| {
            while pos < end {
                if nbits < 32 {
                    if self.pos + 4 <= self.buf.len() {
                        let b = &self.buf[self.pos..self.pos + 4];
                        let word = (b[1] as u64) << 24 | (b[0] as u64) << 16 | (b[3] as u64) << 8 | b[2] as u64;
                        bits = ((bits & mask(nbits)) << 32) | word;
                        self.pos += 4;
                        nbits += 32;
                    } else {
                        self.slow_fill(&mut bits, &mut nbits, input)?;
                    }
                }
                let symbol = Self::lookup(main, bits, &mut nbits) as usize;
                if symbol < 256 {
                    if pos >= window_size {
                        return corrupt("LZX match runs past the end of the window");
                    }
                    self.window[pos] = symbol as u8;
                    pos += 1;
                    continue;
                }
                let symbol = symbol - 256;
                let mut length = symbol & 7;
                if length == PRIMARY_LENGTHS {
                    let Some(lt) = length_tree else {
                        return corrupt("LZX length symbol read from an empty tree");
                    };
                    length += Self::lookup(lt, bits, &mut nbits) as usize;
                }
                length += MIN_MATCH;
                let slot = symbol >> 3;
                let offset: u64;
                if slot == 0 {
                    offset = r0;
                } else if slot == 1 {
                    offset = r1;
                    r1 = r0;
                    r0 = offset;
                } else if slot == 2 {
                    offset = r2;
                    r2 = r0;
                    r0 = offset;
                } else {
                    if nbits < 32 {
                        self.slow_fill(&mut bits, &mut nbits, input)?;
                    }
                    let extra = EXTRA_BITS[slot];
                    let mut off = POSITION_BASE[slot] as u64 - 2;
                    if extra >= 3 && is_aligned {
                        let Some(at) = aligned_tree else {
                            return corrupt("LZX aligned symbol read from an empty tree");
                        };
                        if extra > 3 {
                            nbits -= extra - 3;
                            off += ((bits >> nbits) & mask(extra - 3)) << 3;
                        }
                        let e = at.table[((bits >> (nbits - at.root)) & mask(at.root)) as usize];
                        nbits -= (e & 31) as u32;
                        off += (e >> 5) as u64;
                    } else if extra > 0 {
                        nbits -= extra;
                        off += (bits >> nbits) & mask(extra);
                    }
                    r2 = r1;
                    r1 = r0;
                    r0 = off;
                    offset = off;
                }
                if pos + length > window_size {
                    return corrupt("LZX match runs past the end of the window");
                }
                let p = pos as u64;
                let ws = window_size as u64;
                if offset > p {
                    if offset > decoded || offset - p > ws {
                        return corrupt("LZX match reaches before the stream start");
                    }
                    let src = (ws - (offset - p)) as usize;
                    let first = length.min(window_size - src);
                    self.window.copy_within(src..src + first, pos);
                    if first < length {
                        copy_repeat(&mut self.window, 0, pos + first, length - first);
                    }
                } else if offset >= length as u64 {
                    let src = pos - offset as usize;
                    self.window.copy_within(src..src + length, pos);
                } else {
                    copy_repeat(&mut self.window, pos - offset as usize, pos, length);
                }
                pos += length;
            }
            Ok(())
        })();
        self.r0 = r0;
        self.r1 = r1;
        self.r2 = r2;
        self.bits = bits;
        self.nbits = nbits;
        self.window_pos = pos;
        result?;
        Ok(pos - start)
    }

    fn undo_e8(&self, out: &mut [u8]) {
        let size = out.len();
        if size <= 10 {
            return;
        }
        let file_size: i64 = if self.intel_size >= 1 << 31 { self.intel_size as i64 - (1i64 << 32) } else { self.intel_size as i64 };
        let base = self.offset as i64;
        let limit = size - 10;
        let mut i = 0;
        while i < limit {
            if out[i] != 0xE8 {
                i += 1;
                continue;
            }
            let current = base + i as i64;
            let value = i32::from_le_bytes([out[i + 1], out[i + 2], out[i + 3], out[i + 4]]) as i64;
            if -current <= value && value < file_size {
                let relative = if value >= 0 { value - current } else { value + file_size };
                out[i + 1..i + 5].copy_from_slice(&(relative as u32).to_le_bytes());
            }
            i += 5;
        }
    }
}

/// Copy `length` bytes from `src` to `dst` in `window`; a source that overlaps the
/// destination repeats (Python `_copy`).
fn copy_repeat(window: &mut [u8], src: usize, dst: usize, length: usize) {
    let distance = dst as isize - src as isize;
    if distance >= length as isize || distance <= 0 {
        window.copy_within(src..src + length, dst);
        return;
    }
    for k in 0..length {
        window[dst + k] = window[src + k];
    }
}
