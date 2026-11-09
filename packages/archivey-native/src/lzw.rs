//! Unix `compress` (.Z) LZW: a port of archivey's `LzwState`
//! (`internal/streams/codecs/unix_compress_decoder.py`), including its 9-bit layout
//! probe, CLEAR realignment, padding bookkeeping, truncation evidence and the
//! "hand back what decoded, raise on the next call" rule. The code table is the
//! classic prefix/suffix one rather than the Python flat-or-link entries; the bytes
//! it produces are the same.

use crate::error::DecodeError;

const INITIAL_CODE_WIDTH: u32 = 9;
const MAX_CODE_WIDTH: u32 = 16;
const INITIAL_MASK: u32 = (1 << INITIAL_CODE_WIDTH) - 1;
const CLEAR_CODE: u32 = 256;
const MAGIC: [u8; 2] = [0x1F, 0x9D];
const HEADER_SIZE: usize = 3;
const NINE_BIT_PROBE_BYTES: usize = 64;
const NINE_BIT_CLEAR_EVIDENCE: i64 = 4;

type Err = DecodeError;

fn corrupt(msg: impl Into<String>) -> Err {
    DecodeError::Corrupt(msg.into())
}

fn pymod(a: i64, m: i64) -> i64 {
    a.rem_euclid(m)
}

pub fn parse_header(header: &[u8]) -> Result<(u32, bool), Err> {
    if header.len() < HEADER_SIZE {
        return Err(corrupt("unix-compress (.Z) stream is too short (missing header)"));
    }
    if header[0] != MAGIC[0] || header[1] != MAGIC[1] {
        return Err(corrupt(format!(
            "unix-compress (.Z) magic mismatch (expected 1f 9d, got {:02x} {:02x})",
            header[0], header[1]
        )));
    }
    let flag = header[2];
    let reserved = flag & 0x60;
    if reserved != 0 {
        return Err(DecodeError::Unsupported(format!(
            "unix-compress (.Z) header has unknown reserved flags (0x{reserved:02x} in flag byte 0x{flag:02x}); a damaged header reads the same way"
        )));
    }
    let max_width = (flag & 0x1F) as u32;
    if max_width < INITIAL_CODE_WIDTH {
        return Err(corrupt(format!(
            "unix-compress (.Z) max code width {max_width} is below the minimum of {INITIAL_CODE_WIDTH}"
        )));
    }
    if max_width > MAX_CODE_WIDTH {
        return Err(DecodeError::Unsupported(format!(
            "unix-compress (.Z) max code width {max_width} is not supported: decoders handle up to {MAX_CODE_WIDTH} bits; a damaged header reads the same way"
        )));
    }
    Ok((max_width, flag & 0x80 != 0))
}

pub struct LzwState {
    buf: Vec<u8>,
    pub nine_bit_widens: Option<bool>,
    at_nine_bit_fill: bool,
    finished: bool,
    pub truncation: Option<String>,
    pub header_params: Option<(u32, bool)>,
    need_header: bool,
    seg_comp: i64,
    seg_decomp: i64,
    pending_skip: i64,
    skip_may_end_at: i64,
    skip_reason: &'static str,
    step_output: Vec<u8>,
    raise_after: Option<Err>,
    // Dictionary state.
    max_width: u32,
    block_mode: bool,
    prefix: Vec<u32>,
    suffix: Vec<u8>,
    length: Vec<u32>,
    dict_len: u32,
    starting_code: u32,
    next_code: u32,
    bit_buffer: u64,
    bits_in_buffer: u32,
    prev_code: Option<u32>,
    code_width: u32,
    current_mask: u32,
    bytes_in_era: i64,
    codes_in_era: i64,
}

pub type Units = Vec<(i64, i64)>;

impl LzwState {
    pub fn new(max_width: Option<u32>, block_mode: Option<bool>, nine_bit_widens: Option<bool>) -> Self {
        let mut s = LzwState {
            buf: Vec::new(),
            nine_bit_widens,
            at_nine_bit_fill: false,
            finished: false,
            truncation: None,
            header_params: None,
            need_header: max_width.is_none(),
            seg_comp: 0,
            seg_decomp: 0,
            pending_skip: 0,
            skip_may_end_at: 0,
            skip_reason: "after a CLEAR",
            step_output: Vec::new(),
            raise_after: None,
            max_width: 0,
            block_mode: false,
            prefix: Vec::new(),
            suffix: Vec::new(),
            length: Vec::new(),
            dict_len: 0,
            starting_code: 0,
            next_code: 0,
            bit_buffer: 0,
            bits_in_buffer: 0,
            prev_code: None,
            code_width: INITIAL_CODE_WIDTH,
            current_mask: INITIAL_MASK,
            bytes_in_era: 0,
            codes_in_era: 0,
        };
        if let (Some(w), Some(b)) = (max_width, block_mode) {
            s.init_dictionary(w, b);
            s.header_params = Some((w, b));
        }
        s
    }

    fn init_dictionary(&mut self, max_width: u32, block_mode: bool) {
        self.max_width = max_width;
        self.block_mode = block_mode;
        let size = 1usize << max_width.max(10);
        self.prefix = vec![0; size];
        self.suffix = vec![0; size];
        self.length = vec![0; size];
        for i in 0..256 {
            self.suffix[i] = i as u8;
            self.length[i] = 1;
        }
        self.dict_len = 256;
        if block_mode {
            self.length[256] = 0;
            self.dict_len = 257;
        }
        self.starting_code = self.dict_len;
        self.next_code = self.starting_code;
        self.bit_buffer = 0;
        self.bits_in_buffer = 0;
        self.prev_code = None;
        self.code_width = INITIAL_CODE_WIDTH;
        self.current_mask = INITIAL_MASK;
        self.bytes_in_era = 0;
        self.codes_in_era = if block_mode { 0 } else { -1 };
        self.pending_skip = 0;
        self.skip_may_end_at = 0;
        self.skip_reason = "after a CLEAR";
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn needs_input(&self) -> bool {
        if self.finished {
            return true;
        }
        if self.need_header {
            return self.buf.len() < HEADER_SIZE;
        }
        if self.at_nine_bit_fill && self.nine_bit_widens.is_none() {
            let pad = pymod(-self.bytes_in_era, INITIAL_CODE_WIDTH as i64) as usize;
            return self.buf.len() < pad + NINE_BIT_PROBE_BYTES;
        }
        self.buf.is_empty()
    }

    pub fn feed(&mut self, data: &[u8], max_length: i64) -> Result<(Vec<u8>, Units), Err> {
        if self.finished {
            return Ok((Vec::new(), Vec::new()));
        }
        self.buf.extend_from_slice(data);
        self.process(false, max_length)
    }

    pub fn flush(&mut self) -> Result<(Vec<u8>, Units), Err> {
        let r = self.process(true, -1)?;
        if self.pending_skip != 0 && self.pending_skip != self.skip_may_end_at {
            self.truncation = Some(format!(
                "it ends {} byte(s) short of the padding {}",
                self.pending_skip, self.skip_reason
            ));
        } else if self.header_params.is_some() && self.bits_in_buffer > 0 {
            let leftover = self.bit_buffer & ((1u64 << self.bits_in_buffer) - 1);
            if leftover != 0 {
                self.truncation = Some("nonzero leftover bits after the last complete LZW code".into());
            }
        }
        self.finished = true;
        Ok(r)
    }

    fn process(&mut self, eof: bool, max_length: i64) -> Result<(Vec<u8>, Units), Err> {
        if let Some(e) = self.raise_after.take() {
            // Python keeps raising the same exception on every later call.
            let again = clone_err(&e);
            self.raise_after = Some(e);
            return Err(again);
        }
        let mut out: Vec<u8> = Vec::new();
        let mut units: Units = Vec::new();
        let mut any_part = false;
        let mut got: i64 = 0;
        loop {
            if self.at_nine_bit_fill && !self.settle_nine_bit_fill(eof) {
                break;
            }
            if any_part && 0 <= max_length && max_length <= got {
                break;
            }
            let budget = if max_length < 0 { -1 } else { max_length - got };
            // A step that fails loses its own units, as in Python.
            let mut step_units: Units = Vec::new();
            match self.process_step(eof, budget, &mut step_units) {
                Ok(()) => {
                    units.extend(step_units);
                    got += self.step_output.len() as i64;
                    out.extend_from_slice(&self.step_output);
                    any_part = true;
                }
                Err(e @ DecodeError::Corrupt(_)) | Err(e @ DecodeError::Truncated(_)) => {
                    out.extend_from_slice(&self.step_output);
                    if out.is_empty() {
                        return Err(e);
                    }
                    self.raise_after = Some(clone_err(&e));
                    return Ok((out, units));
                }
                Err(e) => return Err(e),
            }
            if !self.at_nine_bit_fill {
                break;
            }
        }
        Ok((out, units))
    }

    fn settle_nine_bit_fill(&mut self, eof: bool) -> bool {
        let mut widens = self.nine_bit_widens;
        let pad = pymod(-self.bytes_in_era, INITIAL_CODE_WIDTH as i64) as usize;
        if widens.is_none() {
            if self.buf.len() < pad + NINE_BIT_PROBE_BYTES && !eof {
                return false;
            }
            let wlen = self.buf.len().min(pad + NINE_BIT_PROBE_BYTES);
            let window = self.buf[..wlen].to_vec();
            let (ten, ten_checked) = self.nine_bit_layout_breaks(&window, true);
            let (nine, nine_checked) = self.nine_bit_layout_breaks(&window, false);
            let mut w = match (ten, nine) {
                (Some(t), Some(n)) => t >= n,
                (Some(_), None) => false,
                (None, Some(_)) => true,
                (None, None) => {
                    if ten_checked.max(nine_checked) >= NINE_BIT_CLEAR_EVIDENCE && ten_checked != nine_checked {
                        ten_checked > nine_checked
                    } else {
                        true
                    }
                }
            };
            if w && window.len() < pad + NINE_BIT_PROBE_BYTES {
                let tail = window.len() as i64;
                w = (tail == 0 || tail >= pad as i64) && pymod((tail - pad as i64) * 8, 10) != 8;
            }
            self.nine_bit_widens = Some(w);
            widens = Some(w);
        }
        self.at_nine_bit_fill = false;
        if widens != Some(true) {
            return true;
        }
        if pad > 0 {
            let skip = pad.min(self.buf.len());
            self.buf.drain(..skip);
            self.seg_comp += pad as i64;
            if skip < pad {
                self.pending_skip = (pad - skip) as i64;
                self.skip_may_end_at = if skip == 0 { pad as i64 } else { 0 };
                self.skip_reason = "at a code-width increase";
            }
        }
        self.code_width = INITIAL_CODE_WIDTH + 1;
        self.current_mask = (1 << self.code_width) - 1;
        self.next_code = self.current_mask + 1;
        self.bit_buffer = 0;
        self.bits_in_buffer = 0;
        self.bytes_in_era = 0;
        self.codes_in_era = 0;
        true
    }

    fn nine_bit_layout_breaks(&self, window: &[u8], widens: bool) -> (Option<i64>, i64) {
        let block_mode = self.block_mode;
        let (mut pos, mut bits, mut nbits, mut era_bytes, mut width, mut next_code): (i64, u64, u32, i64, u32, u32);
        if widens {
            pos = pymod(-self.bytes_in_era, INITIAL_CODE_WIDTH as i64);
            bits = 0;
            nbits = 0;
            era_bytes = 0;
            width = INITIAL_CODE_WIDTH + 1;
            next_code = 1 << INITIAL_CODE_WIDTH;
        } else {
            pos = 0;
            bits = self.bit_buffer;
            nbits = self.bits_in_buffer;
            era_bytes = self.bytes_in_era;
            width = INITIAL_CODE_WIDTH;
            next_code = 1 << INITIAL_CODE_WIDTH;
        }
        let (mut era_codes, mut after_clear, mut codes, mut checked) = (0i64, false, 0i64, 0i64);
        loop {
            while nbits < width {
                if pos >= window.len() as i64 {
                    return (None, checked);
                }
                bits |= (window[pos as usize] as u64) << nbits;
                nbits += 8;
                pos += 1;
                era_bytes += 1;
            }
            let code = (bits & ((1u64 << width) - 1)) as u32;
            bits >>= width;
            nbits -= width;
            if (code >> INITIAL_CODE_WIDTH) != 0 && width > INITIAL_CODE_WIDTH {
                return (Some(codes), checked);
            }
            if after_clear && (code > next_code || (era_codes == 0 && code > CLEAR_CODE)) {
                return (Some(codes), checked);
            }
            codes += 1;
            if after_clear && code > CLEAR_CODE {
                checked += 1;
            }
            if code == CLEAR_CODE && block_mode {
                let mut i = era_bytes - 1;
                let advanced = pymod(i, width as i64);
                if advanced != 0 {
                    i += width as i64 - advanced;
                }
                pos += i - era_bytes;
                bits = 0;
                nbits = 0;
                era_bytes = 0;
                era_codes = 0;
                width = INITIAL_CODE_WIDTH;
                next_code = CLEAR_CODE + 1;
                after_clear = true;
                continue;
            }
            if after_clear {
                if era_codes != 0 {
                    next_code += 1;
                }
                era_codes += 1;
                if next_code > INITIAL_MASK {
                    return (None, checked);
                }
            }
        }
    }

    /// Append the expansion of `code` (which must be < dict_len) to `out`.
    fn expand_into(&mut self, code: u32, out: &mut Vec<u8>) -> usize {
        let len = self.length[code as usize] as usize;
        let start = out.len();
        out.resize(start + len, 0);
        let mut c = code as usize;
        let mut i = start + len;
        while i > start {
            i -= 1;
            out[i] = self.suffix[c];
            c = self.prefix[c] as usize;
        }
        len
    }

    fn process_step(&mut self, eof: bool, max_length: i64, units: &mut Units) -> Result<(), Err> {
        let mut output = std::mem::take(&mut self.step_output);
        output.clear();
        let r = self.process_step_inner(eof, max_length, units, &mut output);
        self.step_output = output;
        r
    }

    fn process_step_inner(&mut self, eof: bool, max_length: i64, units: &mut Units, output: &mut Vec<u8>) -> Result<(), Err> {
        if self.need_header {
            if self.buf.len() < HEADER_SIZE {
                if eof {
                    if self.buf[..] != MAGIC[..self.buf.len().min(2)] || self.buf.len() > 2 {
                        return Err(corrupt("unix-compress (.Z) stream is too short (missing header)"));
                    }
                    self.truncation = Some("it ends inside the 3-byte header".into());
                }
                return Ok(());
            }
            let header: Vec<u8> = self.buf.drain(..HEADER_SIZE).collect();
            let (w, b) = parse_header(&header)?;
            self.init_dictionary(w, b);
            self.header_params = Some((w, b));
            self.need_header = false;
        }
        if self.pending_skip != 0 {
            let skip = (self.pending_skip as usize).min(self.buf.len());
            self.buf.drain(..skip);
            self.pending_skip -= skip as i64;
            if self.pending_skip != 0 {
                return Ok(());
            }
        }

        let mut bit_buffer = self.bit_buffer;
        let mut bits_in_buffer = self.bits_in_buffer;
        let mut code_width = self.code_width;
        let mut current_mask = self.current_mask;
        let mut next_code = self.next_code;
        let mut prev_code = self.prev_code;
        let mut dict_len = self.dict_len;
        let max_width = self.max_width;
        let mut width_limit = max_width;
        if max_width == INITIAL_CODE_WIDTH && self.nine_bit_widens != Some(false) {
            width_limit += 1;
        }
        let block_mode = self.block_mode;
        let starting_code = self.starting_code;
        let mut seg_comp = self.seg_comp;
        let mut seg_decomp = self.seg_decomp;
        let mut bytes_in_era = self.bytes_in_era;
        let mut codes_in_era = self.codes_in_era;
        let mut codes_per_era: i64 = 1 << (code_width - 1);
        let buf_len = self.buf.len();
        let mut buf_i: usize = 0;
        let mut budget_hit = false;
        let mut last: Option<(u32, usize, usize)> = None;

        while buf_i < buf_len {
            let cur = self.buf[buf_i] as u64;
            buf_i += 1;
            bytes_in_era += 1;
            bit_buffer += cur << bits_in_buffer;
            bits_in_buffer += 8;
            seg_comp += 1;
            let mut cleared = false;
            while bits_in_buffer >= code_width {
                let code = (bit_buffer & current_mask as u64) as u32;
                bit_buffer >>= code_width;
                bits_in_buffer -= code_width;
                codes_in_era += 1;

                if code == CLEAR_CODE && block_mode {
                    let mut i = bytes_in_era - 1;
                    let advanced = pymod(i, code_width as i64);
                    if advanced != 0 {
                        i += code_width as i64 - advanced;
                    }
                    let era_start = buf_i as i64 - bytes_in_era;
                    let target = era_start + i;
                    if target > buf_i as i64 {
                        seg_comp += target - buf_i as i64;
                    } else if target < buf_i as i64 {
                        seg_comp -= buf_i as i64 - target;
                    }
                    units.push((seg_decomp, seg_comp));
                    seg_comp = 0;
                    seg_decomp = 0;
                    dict_len = starting_code;
                    next_code = starting_code;
                    code_width = INITIAL_CODE_WIDTH;
                    current_mask = INITIAL_MASK;
                    bit_buffer = 0;
                    bits_in_buffer = 0;
                    prev_code = None;
                    last = None;
                    bytes_in_era = 0;
                    codes_in_era = 0;
                    codes_per_era = 1 << (code_width - 1);
                    if target > buf_len as i64 {
                        self.pending_skip = target - buf_len as i64;
                        self.skip_may_end_at = 0;
                        self.skip_reason = "after a CLEAR";
                        buf_i = buf_len;
                    } else {
                        buf_i = target as usize;
                    }
                    cleared = true;
                    break;
                }

                let entry_start = output.len();
                let entry_len;
                // The previous entry, when this step wrote it: most entries are it plus
                // one byte, so copying it beats walking the chain a byte at a time.
                let last_here = match (last, prev_code) {
                    (Some((c, at, len)), Some(pc)) if c == pc => Some((at, len)),
                    _ => None,
                };
                if code < dict_len {
                    match last_here {
                        Some((at, len)) if prev_code == Some(code) => {
                            output.extend_from_within(at..at + len);
                            entry_len = len;
                        }
                        Some((at, len))
                            if self.length[code as usize] > 1
                                && Some(self.prefix[code as usize]) == prev_code =>
                        {
                            output.extend_from_within(at..at + len);
                            output.push(self.suffix[code as usize]);
                            entry_len = len + 1;
                        }
                        _ => entry_len = self.expand_into(code, output),
                    }
                } else if code == next_code {
                    let Some(pc) = prev_code else {
                        return Err(corrupt(format!(
                            "unix-compress (.Z) invalid code {code} (expected a literal)"
                        )));
                    };
                    // KwKwK: the previous entry plus its own first byte.
                    let plen = match last_here {
                        Some((at, len)) => {
                            output.extend_from_within(at..at + len);
                            len
                        }
                        None => self.expand_into(pc, output),
                    };
                    let first = output[entry_start];
                    output.push(first);
                    entry_len = plen + 1;
                } else {
                    return Err(corrupt(format!("unix-compress (.Z) invalid code {code} in bitstream")));
                }
                seg_decomp += entry_len as i64;

                if next_code <= current_mask {
                    if let Some(pc) = prev_code {
                        let slot = dict_len as usize;
                        self.prefix[slot] = pc;
                        self.suffix[slot] = output[entry_start];
                        self.length[slot] = self.length[pc as usize] + 1;
                        dict_len += 1;
                        next_code += 1;
                    }
                }
                prev_code = Some(code);
                last = Some((code, entry_start, entry_len));

                if codes_in_era >= codes_per_era && code_width < width_limit {
                    if code_width == max_width {
                        self.at_nine_bit_fill = true;
                        budget_hit = true;
                        break;
                    }
                    let pad = pymod(-bytes_in_era, code_width as i64);
                    if pad != 0 {
                        seg_comp += pad;
                        if buf_i as i64 + pad > buf_len as i64 {
                            self.pending_skip = buf_i as i64 + pad - buf_len as i64;
                            self.skip_may_end_at = if buf_i == buf_len { pad } else { 0 };
                            self.skip_reason = "at a code-width increase";
                            buf_i = buf_len;
                        } else {
                            buf_i += pad as usize;
                        }
                    }
                    code_width += 1;
                    current_mask = (1 << code_width) - 1;
                    bit_buffer = 0;
                    bits_in_buffer = 0;
                    bytes_in_era = 0;
                    codes_in_era = 0;
                    codes_per_era = 1 << (code_width - 1);
                    break;
                }
                if max_length >= 0 && output.len() as i64 >= max_length {
                    budget_hit = true;
                    break;
                }
            }
            if cleared {
                continue;
            }
            if budget_hit {
                break;
            }
        }
        self.buf.drain(..buf_i);
        self.bit_buffer = bit_buffer;
        self.bits_in_buffer = bits_in_buffer;
        self.code_width = code_width;
        self.current_mask = current_mask;
        self.next_code = next_code;
        self.prev_code = prev_code;
        self.dict_len = dict_len;
        self.seg_comp = seg_comp;
        self.seg_decomp = seg_decomp;
        self.bytes_in_era = bytes_in_era;
        self.codes_in_era = codes_in_era;
        Ok(())
    }
}

fn clone_err(e: &Err) -> Err {
    match e {
        DecodeError::Corrupt(m) => DecodeError::Corrupt(m.clone()),
        DecodeError::Truncated(m) => DecodeError::Truncated(m.clone()),
        DecodeError::Unsupported(m) => DecodeError::Unsupported(m.clone()),
        DecodeError::Value(m) => DecodeError::Value(m.clone()),
        DecodeError::Source(never) => match *never {},
    }
}
