//! LZX as Microsoft cabinets store it: a port of archivey's `LzxDecoder`
//! (`internal/streams/codecs/lzx_decoder.py`), which follows libmspack's `lzxd.c`.
//! Same state machine, same checks, same messages, with these intended differences:
//!
//! - A literal written at `window_pos == window_size` raises `Corrupt("LZX match runs
//!   past the end of the window")`, where the Python decoder raises a bare
//!   `IndexError`.
//! - An uncompressed run past the end of the window raises the same `Corrupt`, where
//!   Python's slice assignment grows the window.
//! - After a decode error the decoder's state is left as the error found it; Python
//!   stores a run's locals only on success. The wrapper does not decode again after
//!   an error: it raises the same error from then on.
//!
//! Both decoders take their input pushed and keep their place when it runs out: a
//! `Source` error from `decode_frame` leaves the decoder at the start of the symbol,
//! block header or stored run it could not finish (the input bytes it took kept), so
//! the next call with the same frame size goes on from there.
//!
//! The first two need `window_pos` off a 32 KiB boundary, which an archive cannot
//! cause (CAB frames are 32 KiB but the last): only a caller-chosen frame size or a
//! crafted saved state (`load` takes the saved offset as it is) can put it there.

use crate::kernels::error::{DecodeError, Result};
use crate::kernels::state::{self, Reader};

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
            if e < 17 {
                e as u32
            } else {
                17
            }
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

/// The decoding table for the canonical code of `lengths[:count]`, as archivey's
/// shared `huffman_table.build_table`. A length above 16 (a delta that wrapped below
/// 0) gives its symbol no code, as in lzxd. With `may_be_empty`, `None` for a tree
/// whose lengths are all 0; any other empty tree, and a code that overfills or
/// underfills the code space, is damage.
fn build_table<E>(
    lengths: &[u8],
    count: usize,
    what: &str,
    may_be_empty: bool,
) -> Result<Option<Tree>, E> {
    let mut by_length: [Vec<usize>; (MAX_CODE + 1) as usize] = Default::default();
    let mut nonzero = false;
    for (symbol, &len) in lengths[..count].iter().enumerate() {
        if len != 0 {
            nonzero = true;
            if u32::from(len) <= MAX_CODE {
                by_length[len as usize].push(symbol);
            }
        }
    }
    if !nonzero {
        if may_be_empty {
            return Ok(None);
        }
        return corrupt(format!("LZX {what} tree has no codes"));
    }
    let longest = (1..=MAX_CODE as usize)
        .rev()
        .find(|&n| !by_length[n].is_empty())
        .unwrap_or(0);
    if longest == 0 {
        return corrupt(format!("LZX {what} tree does not fill its code space"));
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

/// lzxd's `z = lens[x] - z; if (z < 0) z += 17;` into an `unsigned char`: pretree
/// symbols 17 to 19 read after a code 19 can leave it below 0, which the byte keeps
/// as 254 or 255, a length no code has.
fn delta(length: u8, code: usize) -> u8 {
    let mut value = i32::from(length) - code as i32;
    if value < 0 {
        value += 17;
    }
    (value & 0xFF) as u8
}

/// Where the decoder gets its input: a cabinet's data blocks, one run at a time.
pub trait Input {
    type Error;
    /// The next run of input bytes, or `None` at the end of the input.
    fn more(&mut self) -> std::result::Result<Option<Vec<u8>>, Self::Error>;
}

#[derive(Clone)]
pub struct LzxDecoder {
    window_bits: u32,
    window_size: usize,
    window: Vec<u8>,
    main_symbols: usize,
    buf: Vec<u8>,
    pos: usize,
    bits: u64,
    nbits: u32,
    padding: usize,
    /// Bits read since the last Huffman symbol began: lzxd.c looks 16 bits ahead
    /// from the start of each symbol, so its look-ahead is `16 - since_symbol`.
    since_symbol: u32,
    main_lengths: Vec<u8>,
    length_lengths: Vec<u8>,
    aligned_lengths: [u8; ALIGNED_SYMBOLS],
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
    /// The frame being decoded once it started, and where in the window it starts.
    /// The input buffer only grows while a frame is in progress (it is trimmed when
    /// one starts), so a place kept to resume from stays valid as input arrives.
    frame_size: Option<usize>,
    frame_start: usize,
}

#[inline(always)]
fn mask(n: u32) -> u64 {
    if n >= 64 {
        u64::MAX
    } else {
        (1u64 << n) - 1
    }
}

impl LzxDecoder {
    pub fn new(window_bits: u32) -> Result<Self> {
        if !(MIN_WINDOW_BITS..=MAX_WINDOW_BITS).contains(&window_bits) {
            return corrupt(format!("LZX window of 2**{window_bits} bytes"));
        }
        let window_size = 1usize << window_bits;
        Ok(LzxDecoder {
            window_bits,
            window_size,
            window: vec![0; window_size],
            main_symbols: NUM_CHARS + (POSITION_SLOTS[(window_bits - 15) as usize] << 3),
            buf: Vec::new(),
            pos: 0,
            bits: 0,
            nbits: 0,
            padding: 0,
            since_symbol: MAX_CODE,
            main_lengths: vec![0; MAIN_MAX + RUN_SLACK],
            length_lengths: vec![0; LENGTH_MAX + RUN_SLACK],
            aligned_lengths: [0; ALIGNED_SYMBOLS],
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
            frame_size: None,
            frame_start: 0,
        })
    }

    pub fn window_bits(&self) -> u32 {
        self.window_bits
    }

    /// Output bytes decoded so far: the sum of the frames' sizes.
    pub fn decoded(&self) -> u64 {
        self.offset
    }

    /// Input the decoder took from its source but has not read yet (the zero padding
    /// after the end of the input left out).
    pub fn unread_input(&self) -> &[u8] {
        let end = self.buf.len().saturating_sub(self.padding).max(self.pos);
        &self.buf[self.pos..end]
    }

    /// Whether the stream still owes the pad byte after an uncompressed block of odd
    /// length: the decoder skips it at the next block header, so at the end of the
    /// stream it is unread, but it is part of the stream.
    pub fn owes_pad_byte(&self) -> bool {
        self.block_type == UNCOMPRESSED && self.block_remaining == 0 && self.block_length & 1 == 1
    }

    /// Whether the decoder has read zero padding past the end of its input.
    pub fn padded(&self) -> bool {
        self.padding > 0
    }

    /// At a frame boundary, the input bytes of the whole words the bit buffer fetched
    /// ahead and has not used (the zero padding left out). They belong to what follows
    /// the frame: at the end of the stream they are not part of it.
    pub fn lookahead(&self) -> &[u8] {
        let words = (self.nbits / 16) as usize * 2;
        let start = self.pos - words.min(self.pos);
        let real_end = self.buf.len().saturating_sub(self.padding);
        &self.buf[start..self.pos.min(real_end).max(start)]
    }

    /// The size of the frame in progress, which ran out of input and waits for more.
    pub fn frame_in_progress(&self) -> Option<usize> {
        self.frame_size
    }

    /// Give the frame in progress a new size, once the output size is known late. The
    /// frame decodes as if it had that size from its start, as long as it has not
    /// decoded past it: a run stops at the first symbol at or past its end either
    /// way. `false` when it has.
    pub fn resize_frame(&mut self, size: usize) -> bool {
        if self.frame_size.is_none() || size == 0 || size > FRAME_SIZE {
            return false;
        }
        if self.window_pos - self.frame_start > size {
            return false;
        }
        self.frame_size = Some(size);
        true
    }

    /// What a block header or the stream header can change, to resume from its start
    /// when it runs out of input: all but the window and the input buffer, which
    /// a header does not write (the buffer only grows inside a frame).
    fn snapshot(&mut self) -> LzxDecoder {
        let window = std::mem::take(&mut self.window);
        let buf = std::mem::take(&mut self.buf);
        let saved = self.clone();
        self.window = window;
        self.buf = buf;
        saved
    }

    fn resume_from(&mut self, mut saved: LzxDecoder) {
        saved.window = std::mem::take(&mut self.window);
        saved.buf = std::mem::take(&mut self.buf);
        *self = saved;
    }

    /// The decoder's state (design D3): everything it consumed, none of the input it
    /// holds unread. Inside a frame it is the place the frame resumes from, with the
    /// frame's output so far in the window. Past the end of its input, the zero
    /// padding it added is saved too, so the restored decoder pads as this one would.
    pub fn save(&self, out: &mut Vec<u8>) {
        out.push(self.window_bits as u8);
        out.extend_from_slice(&self.window);
        // The last bytes read: `align_for_raw` steps back over the bytes still in the
        // bit buffer.
        state::put_bytes(out, &self.buf[self.pos - self.pos.min(8)..self.pos]);
        state::put_u64(out, self.bits);
        out.push(self.nbits as u8);
        // Inside a frame it can be above 16 (fixed-width fields read since a symbol);
        // `realign`, its only reader, treats any value from 16 up the same.
        out.push(self.since_symbol.min(MAX_CODE) as u8);
        out.extend_from_slice(&self.main_lengths);
        out.extend_from_slice(&self.length_lengths);
        out.extend_from_slice(&self.aligned_lengths);
        out.push(
            u8::from(self.main_table.is_some())
                | u8::from(self.length_table.is_some()) << 1
                | u8::from(self.aligned_table.is_some()) << 2,
        );
        state::put_u64(out, self.r0);
        state::put_u64(out, self.r1);
        state::put_u64(out, self.r2);
        out.push(u8::from(self.header_read));
        state::put_u32(out, self.intel_size);
        out.push(u8::from(self.intel_started));
        out.push(self.block_type as u8);
        state::put_u32(out, self.block_length as u32);
        state::put_u32(out, self.block_remaining as u32);
        state::put_u64(out, self.offset);
        state::put_u64(out, self.frame);
        // The frame in progress: its size (0 for none) and the bytes it has so far.
        let (size, done) = match self.frame_size {
            Some(size) => (size, self.window_pos - self.frame_start),
            None => (0, 0),
        };
        state::put_u32(out, size as u32);
        state::put_u32(out, done as u32);
        // Past the end of its input the decoder has read every input byte (each read
        // that appends zero padding goes into it), so only the padding is left: how
        // much was added, and how much of it is not read yet.
        debug_assert!(self.padding == 0 || self.unread_input().is_empty());
        out.push(self.padding as u8);
        out.push(if self.padding > 0 {
            (self.buf.len() - self.pos) as u8
        } else {
            0
        });
    }

    /// Rebuild a decoder from `save`'s bytes, checking them as `decode_frame` checks
    /// its input: nothing out of range is accepted, and nothing larger than the
    /// largest window is allocated.
    pub fn load(r: &mut Reader<'_>) -> Result<Self> {
        let window_bits = u32::from(r.u8()?);
        if !(MIN_WINDOW_BITS..=MAX_WINDOW_BITS).contains(&window_bits) {
            return r.bad(format!("a window of 2**{window_bits} bytes"));
        }
        let mut d = LzxDecoder::new(window_bits)?;
        d.window.copy_from_slice(r.take(d.window_size)?);
        d.buf = r.bytes(8)?.to_vec();
        d.pos = d.buf.len();
        d.bits = r.u64()?;
        d.nbits = u32::from(r.u8()?);
        d.since_symbol = u32::from(r.u8()?);
        if d.nbits > 64 || d.since_symbol > MAX_CODE || (d.nbits / 8) as usize > d.pos {
            return r.bad("a bit buffer out of range");
        }
        let main_len = d.main_lengths.len();
        d.main_lengths.copy_from_slice(r.take(main_len)?);
        let length_len = d.length_lengths.len();
        d.length_lengths.copy_from_slice(r.take(length_len)?);
        d.aligned_lengths.copy_from_slice(r.take(ALIGNED_SYMBOLS)?);
        let trees = r.u8()?;
        if trees > 7 {
            return r.bad(format!("tree flags {trees}"));
        }
        let rebuild = |present: bool, tree: Result<Option<Tree>>| -> Result<Option<Tree>> {
            match (present, tree?) {
                (false, _) => Ok(None),
                (true, Some(t)) => Ok(Some(t)),
                (true, None) => r.bad("an empty tree"),
            }
        };
        d.main_table = rebuild(
            trees & 1 != 0,
            build_table(&d.main_lengths, MAIN_MAX, "main", trees & 1 == 0),
        )?;
        d.length_table = rebuild(
            trees & 2 != 0,
            build_table(&d.length_lengths, LENGTH_MAX, "length", true),
        )?;
        d.aligned_table = rebuild(
            trees & 4 != 0,
            build_table(
                &d.aligned_lengths,
                ALIGNED_SYMBOLS,
                "aligned",
                trees & 4 == 0,
            ),
        )?;
        d.r0 = r.u64()?;
        d.r1 = r.u64()?;
        d.r2 = r.u64()?;
        d.header_read = r.bool()?;
        d.intel_size = r.u32()?;
        d.intel_started = r.bool()?;
        d.block_type = u32::from(r.u8()?);
        d.block_length = r.u32()? as usize;
        d.block_remaining = r.u32()? as usize;
        if d.block_type > UNCOMPRESSED
            || d.block_length >= 1 << 24
            || d.block_remaining > d.block_length
        {
            return r.bad("a block header out of range");
        }
        d.offset = r.u64()?;
        d.frame = r.u64()?;
        d.window_pos = (d.offset % d.window_size as u64) as usize;
        let size = r.u32()? as usize;
        let done = r.u32()? as usize;
        if size > FRAME_SIZE
            || (size == 0 && done != 0)
            || (size > 0 && (done >= size || !d.header_read))
            || d.window_pos + done > d.window_size
        {
            return r.bad(format!("a frame of {size} bytes with {done} decoded"));
        }
        if size > 0 {
            d.frame_size = Some(size);
            d.frame_start = d.window_pos;
            d.window_pos += done;
        }
        d.padding = usize::from(r.u8()?);
        let zeros = usize::from(r.u8()?);
        if d.padding > MAX_PADDING || zeros > d.padding {
            return r.bad(format!("{} bytes of padding, {zeros} unread", d.padding));
        }
        d.buf.resize(d.buf.len() + zeros, 0);
        Ok(d)
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
        while self.buf.len() - self.pos < 2 {
            let data = if self.padding > 0 {
                None
            } else {
                input.more().map_err(DecodeError::Source)?
            };
            match data {
                Some(d) => self.buf.extend_from_slice(&d),
                None => {
                    if self.padding >= MAX_PADDING {
                        return Err(DecodeError::Truncated(
                            "LZX stream ends before its output".into(),
                        ));
                    }
                    self.padding += 2;
                    self.buf.extend_from_slice(&[0, 0]);
                }
            }
        }
        Ok(())
    }

    /// Realign the input to a 16-bit word at the end of a frame, and refuse a stream
    /// that lzxd.c would have read more than two bytes past its end for (the Python
    /// decoder's `_realign`).
    fn realign<E>(&mut self) -> Result<(), E> {
        let unread = ((self.buf.len() - self.pos) * 8) as i64 + i64::from(self.nbits);
        let partial = self.nbits % 16;
        let mut ahead = partial;
        if ahead + self.since_symbol < MAX_CODE {
            ahead += 16;
        }
        if 0 < ahead && ahead < 16 {
            ahead += 16;
        }
        if self.padding > 0
            && i64::from(ahead) > unread - (self.padding * 8) as i64 + (PADDING_ALLOWED * 8) as i64
        {
            return Err(DecodeError::Truncated(
                "LZX stream ends before its output".into(),
            ));
        }
        self.nbits -= partial;
        self.since_symbol = MAX_CODE - (ahead - partial);
        Ok(())
    }

    fn read_bits<I: Input>(&mut self, n: u32, input: &mut I) -> Result<u32, I::Error> {
        if self.nbits < n {
            self.refill(n, input)?;
        }
        self.nbits -= n;
        self.since_symbol += n;
        Ok(((self.bits >> self.nbits) & mask(n)) as u32)
    }

    fn raw_bytes<I: Input>(
        &mut self,
        n: usize,
        input: &mut I,
    ) -> Result<std::ops::Range<usize>, I::Error> {
        debug_assert_eq!(self.nbits, 0);
        while self.buf.len() - self.pos < n {
            let data = if self.padding > 0 {
                None
            } else {
                input.more().map_err(DecodeError::Source)?
            };
            let d = match data {
                Some(d) => d,
                None => {
                    // As lzxd.c, read the two zero bytes past the end, but no further.
                    if self.padding >= PADDING_ALLOWED {
                        return Err(DecodeError::Truncated(
                            "LZX stream ends inside an uncompressed block".into(),
                        ));
                    }
                    self.padding += PADDING_ALLOWED;
                    vec![0; PADDING_ALLOWED]
                }
            };
            self.buf.extend_from_slice(&d);
        }
        let at = self.pos;
        self.pos += n;
        // lzxd.c reads stored bytes as it uses them: it holds nothing ahead.
        self.since_symbol = MAX_CODE;
        Ok(at..at + n)
    }

    fn align_for_raw<I: Input>(&mut self, input: &mut I) -> Result<(), I::Error> {
        let drop = match self.nbits % 16 {
            0 => 16,
            d => d,
        };
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

    fn read_pre_symbol<I: Input>(
        &mut self,
        pre: &Option<Tree>,
        input: &mut I,
    ) -> Result<usize, I::Error> {
        let Some(tree) = pre else {
            return corrupt("LZX pretree symbol read from an empty tree");
        };
        if self.nbits < MAX_CODE {
            self.refill(MAX_CODE, input)?;
        }
        let (bits, mut nbits) = (self.bits, self.nbits);
        let start = nbits;
        let root = tree.root;
        let mut entry = tree.table[((bits >> (nbits - root)) & mask(root)) as usize];
        if entry < 0 {
            nbits -= root;
            entry = !entry;
            let sub = (entry & 31) as u32;
            entry =
                tree.table[(entry >> 5) as usize + ((bits >> (nbits - sub)) & mask(sub)) as usize];
        }
        self.nbits = nbits - (entry & 31) as u32;
        self.since_symbol = start - self.nbits;
        Ok((entry >> 5) as usize)
    }

    fn read_lengths<I: Input>(
        &mut self,
        main: bool,
        first: usize,
        last: usize,
        input: &mut I,
    ) -> Result<(), I::Error> {
        let mut pre = [0u8; PRETREE_SYMBOLS];
        for p in pre.iter_mut() {
            *p = self.read_bits(4, input)? as u8;
        }
        let table = build_table(&pre, PRETREE_SYMBOLS, "pretree", false)?;
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
                let value = delta(lengths[x], code);
                lengths[x..x + run].fill(value);
                x += run;
            } else {
                let lengths = self.lengths(main);
                lengths[x] = delta(lengths[x], code);
                x += 1;
            }
        }
        Ok(())
    }

    fn lengths(&mut self, main: bool) -> &mut Vec<u8> {
        if main {
            &mut self.main_lengths
        } else {
            &mut self.length_lengths
        }
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
            self.aligned_table = build_table(&aligned, ALIGNED_SYMBOLS, "aligned", false)?;
            self.aligned_lengths = aligned;
        }
        if block_type == VERBATIM || block_type == ALIGNED {
            self.read_lengths(true, 0, NUM_CHARS, input)?;
            let ms = self.main_symbols;
            self.read_lengths(true, NUM_CHARS, ms, input)?;
            self.main_table = build_table(&self.main_lengths, MAIN_MAX, "main", false)?;
            if self.main_lengths[0xE8] != 0 {
                self.intel_started = true;
            }
            self.read_lengths(false, 0, LENGTH_SYMBOLS, input)?;
            self.length_table = build_table(&self.length_lengths, LENGTH_MAX, "length", true)?;
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

    pub fn decode_frame<I: Input>(
        &mut self,
        frame_size: usize,
        input: &mut I,
    ) -> Result<Vec<u8>, I::Error> {
        match self.frame_size {
            None => {
                if !(frame_size > 0 && frame_size <= FRAME_SIZE) {
                    return Err(DecodeError::Value(format!("frame size {frame_size}")));
                }
                // Trim the input read, keeping the last few bytes: words read ahead
                // into the bit buffer go back to the byte input before an
                // uncompressed block (`align_for_raw`).
                let drop = self.pos - self.pos.min(8);
                if drop > 4096 {
                    self.buf.drain(..drop);
                    self.pos -= drop;
                }
                if !self.header_read {
                    let saved = self.snapshot();
                    let header = (|| {
                        if self.read_bits(1, input)? != 0 {
                            let high = self.read_bits(16, input)?;
                            self.intel_size = (high << 16) | self.read_bits(16, input)?;
                        }
                        Ok(())
                    })();
                    if let Err(e) = header {
                        if matches!(e, DecodeError::Source(_)) {
                            self.resume_from(saved);
                        }
                        return Err(e);
                    }
                    self.header_read = true;
                }
                self.frame_size = Some(frame_size);
                self.frame_start = self.window_pos;
            }
            Some(size) if size != frame_size => {
                return Err(DecodeError::Value(format!(
                    "frame size {frame_size} for a frame started at {size}"
                )));
            }
            Some(_) => {}
        }
        let frame_start = self.frame_start;
        loop {
            let so_far = self.window_pos - frame_start;
            if so_far >= frame_size {
                break;
            }
            let todo = frame_size - so_far;
            if self.block_remaining == 0 {
                let saved = self.snapshot();
                if let Err(e) = self.read_block_header(input) {
                    if matches!(e, DecodeError::Source(_)) {
                        self.resume_from(saved);
                    }
                    return Err(e);
                }
            }
            let run = self.block_remaining.min(todo);
            let done = if self.block_type == UNCOMPRESSED {
                let pos = self.window_pos;
                if pos + run > self.window_size {
                    return corrupt("LZX match runs past the end of the window");
                }
                let (at, since) = (self.pos, self.since_symbol);
                let r = match self.raw_bytes(run, input) {
                    Ok(r) => r,
                    Err(e) => {
                        if matches!(e, DecodeError::Source(_)) {
                            (self.pos, self.since_symbol) = (at, since);
                        }
                        return Err(e);
                    }
                };
                self.window[pos..pos + run].copy_from_slice(&self.buf[r]);
                self.window_pos = pos + run;
                run
            } else {
                let before = self.window_pos;
                match self.decode_run(run, input) {
                    Ok(done) => done,
                    Err(e) => {
                        if matches!(e, DecodeError::Source(_)) {
                            // The run stopped at the start of a symbol: keep what it
                            // decoded.
                            self.block_remaining -= self.window_pos - before;
                        }
                        return Err(e);
                    }
                }
            };
            if done > self.block_remaining {
                return corrupt("LZX match runs past the end of its block");
            }
            self.block_remaining -= done;
        }
        self.frame_size = None;
        if self.window_pos - frame_start != frame_size {
            return corrupt("LZX match runs past the end of a frame");
        }
        self.realign()?;
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
            entry =
                tree.table[(entry >> 5) as usize + ((bits >> (*nbits - sub)) & mask(sub)) as usize];
        }
        *nbits -= (entry & 31) as u32;
        entry >> 5
    }

    fn slow_fill<I: Input>(
        &mut self,
        bits: &mut u64,
        nbits: &mut u32,
        input: &mut I,
    ) -> Result<(), I::Error> {
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
        // `nbits` where the last Huffman symbol began, for `since_symbol`; set so that
        // a run with no symbols (an empty block) leaves it as it was.
        let mut top = nbits + self.since_symbol;
        // Where the input ran out: the bit buffer, input position, `top`, repeated
        // offsets and window position at the start of the symbol it ran out in.
        #[allow(clippy::type_complexity)]
        let mut stop: Option<(u64, u32, usize, u32, u64, u64, u64, usize)> = None;
        let result: Result<(), I::Error> = (|| {
            while pos < end {
                if nbits < 32 {
                    if self.pos + 4 <= self.buf.len() {
                        let b = &self.buf[self.pos..self.pos + 4];
                        let word = (b[1] as u64) << 24
                            | (b[0] as u64) << 16
                            | (b[3] as u64) << 8
                            | b[2] as u64;
                        bits = ((bits & mask(nbits)) << 32) | word;
                        self.pos += 4;
                        nbits += 32;
                    } else {
                        let bpos = self.pos;
                        if let Err(e) = self.slow_fill(&mut bits, &mut nbits, input) {
                            // Resume from this symbol's start: the locals as they are
                            // (`slow_fill` changes them only when it succeeds).
                            stop = Some((bits, nbits, bpos, top, r0, r1, r2, pos));
                            return Err(e);
                        }
                    }
                }
                // The symbol's start, to resume from if its extra bits run out.
                let (start_nbits, start_top, start_bpos) = (nbits, top, self.pos);
                top = nbits;
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
                    top = nbits;
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
                        let filled = nbits;
                        if let Err(e) = self.slow_fill(&mut bits, &mut nbits, input) {
                            // Only the codes read since the symbol began changed
                            // `nbits`; the repeated offsets change after this.
                            stop =
                                Some((bits, start_nbits, start_bpos, start_top, r0, r1, r2, pos));
                            return Err(e);
                        }
                        top += nbits - filled;
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
                        top = nbits;
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
        if let Some((b, n, bpos, t, a0, a1, a2, p)) = stop {
            if matches!(result, Err(DecodeError::Source(_))) {
                (self.bits, self.nbits, self.pos) = (b, n, bpos);
                (self.r0, self.r1, self.r2) = (a0, a1, a2);
                // Unused: the symbol is decoded again, and its start sets `top` before
                // anything reads it. 0 keeps a saved state within `load`'s range.
                let _ = t;
                self.since_symbol = 0;
                self.window_pos = p;
                return result.map(|()| 0);
            }
        }
        self.r0 = r0;
        self.r1 = r1;
        self.r2 = r2;
        self.bits = bits;
        self.nbits = nbits;
        self.window_pos = pos;
        result?;
        self.since_symbol = top - nbits;
        Ok(pos - start)
    }

    fn undo_e8(&self, out: &mut [u8]) {
        let size = out.len();
        if size <= 10 {
            return;
        }
        let file_size: i64 = if self.intel_size >= 1 << 31 {
            self.intel_size as i64 - (1i64 << 32)
        } else {
            self.intel_size as i64
        };
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
                let relative = if value >= 0 {
                    value - current
                } else {
                    value + file_size
                };
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
