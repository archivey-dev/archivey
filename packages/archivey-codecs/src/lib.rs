//! Python bindings for archivey-codecs.
//!
//! The kernels (`kernels/`) know nothing about Python. This module gives them the
//! standard-library shapes of archivey's design (openspec change
//! `rust-codecs-package`, D2 and D3): `hashlib`-style hashes, `zlib.crc32`-style
//! functions, `lzma.LZMADecompressor`-style decompressors, length-keeping transforms,
//! one-shot block functions, and the `CodecError` family.
//!
//! Input: an immutable `bytes` object is read in place, and the GIL is released while
//! a kernel reads it (by the CRC only from 64 KiB up); any other buffer is copied
//! first, so no other thread can change the bytes a kernel is reading. The private
//! LZX and BCJ2 classes hold the GIL: they call back into Python for input.

pub mod kernels;

use std::borrow::Cow;

use kernels::error::DecodeError;
use kernels::{bcj2, crc16, filters, lzo, lzw, lzx, zipcrypto};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyEOFError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyInt};
use pyo3::{PyTraverseError, PyVisit};

pyo3::create_exception!(
    _codecs,
    CodecError,
    PyValueError,
    "A codec refused its input."
);
pyo3::create_exception!(
    _codecs,
    CorruptDataError,
    CodecError,
    "The data is damaged."
);
pyo3::create_exception!(
    _codecs,
    TruncatedDataError,
    CodecError,
    "The data ends early."
);
pyo3::create_exception!(
    _codecs,
    UnsupportedDataError,
    CodecError,
    "The data, or a saved state, uses something this kernel does not read."
);

/// Each kernel's revision (design D4): raised whenever the kernel's output bytes,
/// error kinds or messages, or reported state change. A change to a signature,
/// attribute name or error class takes a new key instead.
const KERNELS: &[(&str, u32)] = &[
    ("arm64", 1),
    ("crc16_arc", 1),
    ("lzo1x", 1),
    ("lzw", 1),
    ("riscv", 1),
    ("zipcrypto", 1),
];

fn revision(name: &str) -> u32 {
    KERNELS
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, r)| *r)
        .unwrap_or(0)
}

/// `hashlib` releases the GIL for inputs above 2 KiB; the CRC is cheap enough that the
/// release only pays off higher.
const GIL_RELEASE_BYTES: usize = 64 * 1024;

fn to_py0(err: DecodeError) -> PyErr {
    match err {
        DecodeError::Corrupt(m) => CorruptDataError::new_err(m),
        DecodeError::Truncated(m) => TruncatedDataError::new_err(m),
        DecodeError::Unsupported(m) => UnsupportedDataError::new_err(m),
        DecodeError::Value(m) => PyValueError::new_err(m),
        DecodeError::Source(never) => match never {},
    }
}

fn to_py(err: DecodeError<PyErr>) -> PyErr {
    match err {
        DecodeError::Corrupt(m) => CorruptDataError::new_err(m),
        DecodeError::Truncated(m) => TruncatedDataError::new_err(m),
        DecodeError::Unsupported(m) => UnsupportedDataError::new_err(m),
        DecodeError::Value(m) => PyValueError::new_err(m),
        DecodeError::Source(e) => e,
    }
}

/// The bytes of a bytes-like argument: borrowed from an immutable `bytes`, copied from
/// anything else that exports a buffer.
fn input<'a>(obj: &'a Bound<'_, PyAny>) -> PyResult<Cow<'a, [u8]>> {
    if let Ok(b) = obj.cast::<PyBytes>() {
        return Ok(Cow::Borrowed(b.as_bytes()));
    }
    if let Ok(buffer) = PyBuffer::<u8>::get(obj) {
        return Ok(Cow::Owned(buffer.to_vec(obj.py())?));
    }
    // A buffer of wider items (`array.array("I")`): its bytes, as hashlib reads them.
    let bytes = pyo3::types::PyMemoryView::from(obj)?.call_method1("cast", ("B",))?;
    let buffer = PyBuffer::<u8>::get(&bytes)?;
    Ok(Cow::Owned(buffer.to_vec(obj.py())?))
}

// ── Saved state ─────────────────────────────────────────────────────────────────────

/// A saved state starts with the kernel's name and revision, so `from_state` refuses a
/// state from another kernel or another revision (design D3).
fn state_header(kernel: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.push(kernel.len() as u8);
    out.extend_from_slice(kernel.as_bytes());
    out.extend_from_slice(&revision(kernel).to_le_bytes());
    out
}

/// Reads a saved state's fields, refusing a cut-off state as damage.
struct StateReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> StateReader<'a> {
    fn open(kernel: &str, data: &'a [u8]) -> PyResult<Self> {
        let cut = || CorruptDataError::new_err(format!("the {kernel} state is cut off"));
        let n = *data.first().ok_or_else(cut)? as usize;
        let name = data.get(1..1 + n).ok_or_else(cut)?;
        let rev = data.get(1 + n..5 + n).ok_or_else(cut)?;
        let rev = u32::from_le_bytes([rev[0], rev[1], rev[2], rev[3]]);
        if name != kernel.as_bytes() || rev != revision(kernel) {
            return Err(UnsupportedDataError::new_err(format!(
                "a state from {} revision {rev}, not {kernel} revision {}",
                String::from_utf8_lossy(name),
                revision(kernel)
            )));
        }
        Ok(StateReader { data, pos: 5 + n })
    }

    fn take(&mut self, n: usize, kernel: &str) -> PyResult<&'a [u8]> {
        let got = self
            .data
            .get(self.pos..self.pos + n)
            .ok_or_else(|| CorruptDataError::new_err(format!("the {kernel} state is cut off")))?;
        self.pos += n;
        Ok(got)
    }

    fn u32(&mut self, kernel: &str) -> PyResult<u32> {
        let b = self.take(4, kernel)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self, kernel: &str) -> PyResult<u64> {
        let b = self.take(8, kernel)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    fn finish(&self, kernel: &str) -> PyResult<()> {
        if self.pos != self.data.len() {
            return Err(CorruptDataError::new_err(format!(
                "{} bytes follow the {kernel} state",
                self.data.len() - self.pos
            )));
        }
        Ok(())
    }
}

// ── CRC-16/ARC ──────────────────────────────────────────────────────────────────────

fn crc16_update(py: Python<'_>, crc: u16, data: &Bound<'_, PyAny>) -> PyResult<u16> {
    let data = input(data)?;
    if data.len() >= GIL_RELEASE_BYTES {
        let slice: &[u8] = &data;
        Ok(py.detach(|| crc16::crc16_arc(slice, crc)))
    } else {
        Ok(crc16::crc16_arc(&data, crc))
    }
}

/// CRC-16/ARC of `data`, continuing from `value`, like `zlib.crc32`. Unlike
/// `zlib.crc32`, `value` must be in 0 to 0xFFFF: an int outside it raises `ValueError`.
#[pyfunction]
#[pyo3(signature = (data, value = None, /))]
fn crc16_arc(
    py: Python<'_>,
    data: &Bound<'_, PyAny>,
    value: Option<&Bound<'_, PyAny>>,
) -> PyResult<u32> {
    let Some(value) = value else {
        return Ok(u32::from(crc16_update(py, 0, data)?));
    };
    // A CRC-16 has 16 bits: a value outside them is refused rather than masked, since
    // it can only be a caller's mistake. Any int is compared, however large.
    let value = match value.extract::<u16>() {
        Ok(v) => v,
        Err(_) if value.is_instance_of::<PyInt>() => {
            return Err(PyValueError::new_err(format!(
                "CRC-16 value {value} is outside 0 to 0xFFFF"
            )));
        }
        Err(e) => return Err(e),
    };
    Ok(u32::from(crc16_update(py, value, data)?))
}

/// A running CRC-16/ARC with the `hashlib` interface; `digest()` is big-endian.
#[pyclass(module = "archivey_codecs", name = "Crc16Arc")]
#[derive(Clone)]
struct Crc16Arc {
    crc: u16,
}

#[pymethods]
impl Crc16Arc {
    #[new]
    #[pyo3(signature = (data = None, /))]
    fn new(py: Python<'_>, data: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let crc = match data {
            Some(d) => crc16_update(py, 0, d)?,
            None => 0,
        };
        Ok(Crc16Arc { crc })
    }

    fn update(&mut self, py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<()> {
        self.crc = crc16_update(py, self.crc, data)?;
        Ok(())
    }

    fn digest<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.crc.to_be_bytes())
    }

    fn hexdigest(&self) -> String {
        format!("{:04x}", self.crc)
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    #[getter]
    fn name(&self) -> &'static str {
        "crc16_arc"
    }

    #[getter]
    fn digest_size(&self) -> usize {
        2
    }

    #[getter]
    fn block_size(&self) -> usize {
        1
    }
}

// ── LZO1X ───────────────────────────────────────────────────────────────────────────

/// Decode one LZO1X block whose output is exactly `out_size` bytes.
#[pyfunction]
#[pyo3(signature = (block, /, *, out_size))]
fn lzo1x_decompress<'py>(
    py: Python<'py>,
    block: &Bound<'py, PyAny>,
    out_size: usize,
) -> PyResult<Bound<'py, PyBytes>> {
    let data = input(block)?;
    let slice: &[u8] = &data;
    let out = py
        .detach(|| lzo::lzo1x_decompress(slice, out_size))
        .map_err(to_py0)?;
    if out.len() != out_size {
        return Err(CorruptDataError::new_err(format!(
            "the block decodes to {} bytes, not {out_size}",
            out.len()
        )));
    }
    Ok(PyBytes::new(py, &out))
}

// ── ARM64 and RISC-V branch filters ─────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Branch {
    Arm64,
    Riscv,
}

impl Branch {
    fn kernel(self) -> &'static str {
        match self {
            Branch::Arm64 => "arm64",
            Branch::Riscv => "riscv",
        }
    }

    /// The most `decode()` holds back: ARM64 instructions are 4 bytes, so a cut one
    /// leaves at most 3; the RISC-V filter needs 8 bytes to read an instruction pair,
    /// so it holds at most 7.
    fn max_held(self) -> usize {
        match self {
            Branch::Arm64 => 3,
            Branch::Riscv => 7,
        }
    }

    fn decode(self, data: &[u8], pc: u64) -> Vec<u8> {
        match self {
            Branch::Arm64 => filters::arm64_decode(data, pc),
            Branch::Riscv => filters::riscv_decode(data, pc),
        }
    }
}

/// A branch filter's decoder: each `decode()` returns what can be decoded so far and
/// holds back the bytes an instruction cut at the end may still need; `flush()`
/// returns those unchanged, as liblzma and 7-Zip do at the end of the input.
#[derive(Clone)]
struct BranchState {
    kind: Branch,
    pc: u64,
    held: Vec<u8>,
    total_in: u64,
    total_out: u64,
}

impl BranchState {
    fn decode(&mut self, py: Python<'_>, data: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
        let data = input(data)?;
        if data.is_empty() {
            // As archivey's Python filter decoder: an empty chunk decodes nothing.
            return Ok(Vec::new());
        }
        self.total_in += data.len() as u64;
        let mut buf = std::mem::take(&mut self.held);
        buf.extend_from_slice(&data);
        let (kind, pc) = (self.kind, self.pc);
        let out = py.detach(|| kind.decode(&buf, pc));
        self.held = buf[out.len()..].to_vec();
        self.pc = self.pc.wrapping_add(out.len() as u64);
        self.total_out += out.len() as u64;
        Ok(out)
    }

    fn flush(&mut self) -> Vec<u8> {
        let out = std::mem::take(&mut self.held);
        self.pc = self.pc.wrapping_add(out.len() as u64);
        self.total_out += out.len() as u64;
        out
    }

    fn getstate(&self) -> Vec<u8> {
        let mut out = state_header(self.kind.kernel());
        out.extend_from_slice(&self.pc.to_le_bytes());
        out.extend_from_slice(&self.total_in.to_le_bytes());
        out.extend_from_slice(&self.total_out.to_le_bytes());
        out.push(self.held.len() as u8);
        out.extend_from_slice(&self.held);
        out
    }

    fn from_state(kind: Branch, state: &[u8]) -> PyResult<Self> {
        let k = kind.kernel();
        let mut r = StateReader::open(k, state)?;
        let pc = r.u64(k)?;
        let total_in = r.u64(k)?;
        let total_out = r.u64(k)?;
        let n = r.take(1, k)?[0] as usize;
        if n > kind.max_held() {
            return Err(CorruptDataError::new_err(format!(
                "the {k} state holds back {n} bytes"
            )));
        }
        let held = r.take(n, k)?.to_vec();
        r.finish(k)?;
        Ok(BranchState {
            kind,
            pc,
            held,
            total_in,
            total_out,
        })
    }
}

macro_rules! branch_decoder {
    ($rust:ident, $name:literal, $kind:expr) => {
        #[pyclass(module = "archivey_codecs.filters", name = $name)]
        #[derive(Clone)]
        struct $rust {
            inner: BranchState,
        }

        #[pymethods]
        impl $rust {
            #[new]
            #[pyo3(signature = (start_offset = 0))]
            fn new(start_offset: u64) -> Self {
                $rust {
                    inner: BranchState {
                        kind: $kind,
                        pc: start_offset,
                        held: Vec::new(),
                        total_in: 0,
                        total_out: 0,
                    },
                }
            }

            fn decode<'py>(
                &mut self,
                py: Python<'py>,
                data: &Bound<'py, PyAny>,
            ) -> PyResult<Bound<'py, PyBytes>> {
                let out = self.inner.decode(py, data)?;
                Ok(PyBytes::new(py, &out))
            }

            fn flush<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
                PyBytes::new(py, &self.inner.flush())
            }

            fn copy(&self) -> Self {
                self.clone()
            }

            fn getstate<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
                PyBytes::new(py, &self.inner.getstate())
            }

            #[classmethod]
            fn from_state(
                _cls: &Bound<'_, pyo3::types::PyType>,
                state: &Bound<'_, PyAny>,
            ) -> PyResult<Self> {
                let state = input(state)?;
                Ok($rust {
                    inner: BranchState::from_state($kind, &state)?,
                })
            }

            #[getter]
            fn total_in(&self) -> u64 {
                self.inner.total_in
            }

            #[getter]
            fn total_out(&self) -> u64 {
                self.inner.total_out
            }
        }
    };
}

branch_decoder!(Arm64Decoder, "Arm64Decoder", Branch::Arm64);
branch_decoder!(RiscvDecoder, "RiscvDecoder", Branch::Riscv);

// ── ZipCrypto ───────────────────────────────────────────────────────────────────────

/// Traditional PKWARE encryption (ZipCrypto): a stream cipher, so `decrypt()` returns
/// exactly as many bytes as it is given.
#[pyclass(module = "archivey_codecs.zipcrypto", name = "Decryptor")]
#[derive(Clone)]
struct ZipCryptoDecryptor {
    keys: zipcrypto::Keys,
    total_in: u64,
}

#[pymethods]
impl ZipCryptoDecryptor {
    #[new]
    fn new(password: &Bound<'_, PyAny>) -> PyResult<Self> {
        let password = input(password)?;
        Ok(ZipCryptoDecryptor {
            keys: zipcrypto::Keys::new(&password),
            total_in: 0,
        })
    }

    fn decrypt<'py>(
        &mut self,
        py: Python<'py>,
        data: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = input(data)?;
        let mut buf = data.into_owned();
        let mut keys = self.keys;
        py.detach(|| keys.decrypt_in_place(&mut buf));
        self.keys = keys;
        self.total_in += buf.len() as u64;
        Ok(PyBytes::new(py, &buf))
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    fn getstate<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let mut out = state_header("zipcrypto");
        for k in [self.keys.k0, self.keys.k1, self.keys.k2] {
            out.extend_from_slice(&k.to_le_bytes());
        }
        out.extend_from_slice(&self.total_in.to_le_bytes());
        PyBytes::new(py, &out)
    }

    #[classmethod]
    fn from_state(
        _cls: &Bound<'_, pyo3::types::PyType>,
        state: &Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        let state = input(state)?;
        let mut r = StateReader::open("zipcrypto", &state)?;
        let keys = zipcrypto::Keys {
            k0: r.u32("zipcrypto")?,
            k1: r.u32("zipcrypto")?,
            k2: r.u32("zipcrypto")?,
        };
        let total_in = r.u64("zipcrypto")?;
        r.finish("zipcrypto")?;
        Ok(ZipCryptoDecryptor { keys, total_in })
    }

    #[getter]
    fn total_in(&self) -> u64 {
        self.total_in
    }
}

// ── Unix compress (LZW) ─────────────────────────────────────────────────────────────

/// Unix `compress` (`.Z`) with the `lzma.LZMADecompressor` interface, plus `flush()`:
/// the format has no end marker, so the caller says when the input has ended.
///
/// `max_length` bounds what each call decodes, `flush()` included: the kernel's
/// final, uncapped pass runs only once less than one code of input is left.
#[pyclass(module = "archivey_codecs.lzw", name = "Decompressor")]
#[derive(Clone)]
struct LzwDecompressor {
    inner: lzw::LzwState,
    /// Decoded output past the last call's `max_length`, from `held_pos` on: the
    /// kernel stops after the entry that reaches its cap, and one entry can be long.
    held: Vec<u8>,
    held_pos: usize,
    /// `flush()` was called: the input has ended.
    flushed: bool,
    /// The header is read from the stream, so offsets count its 3 bytes.
    header_in_stream: bool,
    /// Where the last CLEAR's segment ends: (input, output) offsets.
    clear_at: (u64, u64),
    clear_offsets: Vec<(u64, u64)>,
    /// Bytes passed to `decompress()`.
    fed: u64,
    total_out: u64,
}

impl LzwDecompressor {
    fn held_len(&self) -> usize {
        self.held.len() - self.held_pos
    }

    fn note_units(&mut self, units: lzw::Units) {
        if self.clear_at == (0, 0) && self.header_in_stream && self.inner.header_params.is_some() {
            self.clear_at = (3, 0);
        }
        for (decomp, comp) in units {
            self.clear_at.0 += comp as u64;
            self.clear_at.1 += decomp as u64;
            self.clear_offsets.push(self.clear_at);
        }
    }

    /// One kernel step: decode under `budget`, or after `flush()` with less than one
    /// code left, run the final pass.
    fn step(&mut self, py: Python<'_>, budget: i64) -> Result<Vec<u8>, DecodeError> {
        let inner = &mut self.inner;
        let (out, units) = if self.flushed && inner.needs_input() {
            inner.flush()?
        } else {
            let before = inner.held_input();
            let (out, units) = py.detach(|| inner.feed(&[], budget))?;
            if self.flushed && out.is_empty() && inner.held_input() == before {
                // Nothing moved: what is left is the kernel's to finish.
                let (more, more_units) = inner.flush()?;
                let mut units = units;
                units.extend(more_units);
                (more, units)
            } else {
                (out, units)
            }
        };
        self.note_units(units);
        Ok(out)
    }

    /// Up to `max_length` bytes: held output first, then what the kernel decodes.
    fn produce(&mut self, py: Python<'_>, max_length: i64) -> PyResult<Vec<u8>> {
        let want = if max_length < 0 {
            usize::MAX
        } else {
            max_length as usize
        };
        self.clear_offsets.clear();
        let mut out = Vec::new();
        loop {
            let n = self.held_len().min(want - out.len());
            out.extend_from_slice(&self.held[self.held_pos..self.held_pos + n]);
            self.held_pos += n;
            if out.len() >= want {
                break;
            }
            let done = if self.flushed {
                self.inner.is_finished()
            } else {
                self.inner.needs_input()
            };
            if done {
                break;
            }
            let budget = if max_length < 0 {
                -1
            } else {
                (want - out.len()) as i64
            };
            match self.step(py, budget) {
                Ok(more) => {
                    let empty = more.is_empty();
                    self.held.drain(..self.held_pos);
                    self.held_pos = 0;
                    self.held.extend_from_slice(&more);
                    if empty && !self.flushed {
                        break;
                    }
                }
                // The kernel raises the same error again on the next call: give back
                // the bytes before it first.
                Err(_) if !out.is_empty() => break,
                Err(e) => return Err(to_py0(e)),
            }
        }
        if self.held_pos == self.held.len() {
            self.held.clear();
            self.held_pos = 0;
        }
        self.total_out += out.len() as u64;
        Ok(out)
    }
}

#[pymethods]
impl LzwDecompressor {
    #[new]
    #[pyo3(signature = (*, max_width = None, block_mode = None, nine_bit_widens = None))]
    fn new(
        max_width: Option<u32>,
        block_mode: Option<bool>,
        nine_bit_widens: Option<bool>,
    ) -> PyResult<Self> {
        // As in the Python twin, `max_width` needs `block_mode`, and a lone
        // `block_mode` is ignored (the header is read from the stream).
        if max_width.is_some() && block_mode.is_none() {
            return Err(PyValueError::new_err(
                "give block_mode with max_width (a stream without its header)",
            ));
        }
        if let Some(w) = max_width {
            if !(9..=16).contains(&w) {
                return Err(PyValueError::new_err(format!(
                    "max_width {w} is outside 9 to 16"
                )));
            }
        }
        Ok(LzwDecompressor {
            inner: lzw::LzwState::new(max_width, block_mode, nine_bit_widens),
            held: Vec::new(),
            held_pos: 0,
            flushed: false,
            header_in_stream: max_width.is_none(),
            clear_at: (0, 0),
            clear_offsets: Vec::new(),
            fed: 0,
            total_out: 0,
        })
    }

    #[pyo3(signature = (data, max_length = -1))]
    fn decompress<'py>(
        &mut self,
        py: Python<'py>,
        data: &Bound<'py, PyAny>,
        max_length: i64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        if self.eof() {
            return Err(PyEOFError::new_err("End of stream already reached"));
        }
        if self.flushed {
            return Err(PyValueError::new_err("decompress() after flush()"));
        }
        let data = input(data)?;
        self.clear_offsets.clear();
        if !data.is_empty() {
            // A feed with no room decodes at most one entry: mostly it queues the input.
            let slice: &[u8] = &data;
            let inner = &mut self.inner;
            let got = py.detach(|| inner.feed(slice, 0));
            // The kernel queues the input whether or not it then fails.
            self.fed += data.len() as u64;
            match got {
                Ok((out, units)) => {
                    self.held.extend_from_slice(&out);
                    self.note_units(units);
                }
                // Output decoded before the error comes first; the kernel raises the
                // same error again on the call after it.
                Err(_) if self.held_len() > 0 => {}
                Err(e) => return Err(to_py0(e)),
            }
        }
        let first = std::mem::take(&mut self.clear_offsets);
        let out = self.produce(py, max_length)?;
        let mut all = first;
        all.append(&mut self.clear_offsets);
        self.clear_offsets = all;
        Ok(PyBytes::new(py, &out))
    }

    /// Mark the end of the input and return the rest of the output, at most
    /// `max_length` bytes a call; `eof` is true once all of it is returned.
    #[pyo3(signature = (max_length = -1))]
    fn flush<'py>(&mut self, py: Python<'py>, max_length: i64) -> PyResult<Bound<'py, PyBytes>> {
        self.flushed = true;
        let out = self.produce(py, max_length)?;
        Ok(PyBytes::new(py, &out))
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    #[getter]
    fn eof(&self) -> bool {
        self.flushed && self.inner.is_finished() && self.held_len() == 0
    }

    #[getter]
    fn needs_input(&self) -> bool {
        !self.flushed && self.held_len() == 0 && self.inner.needs_input()
    }

    #[getter]
    fn unused_data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        // The stream ends where its input ends: nothing follows it.
        PyBytes::new(py, b"")
    }

    /// After `flush()`, what showed that the stream was cut short, else `None`.
    #[getter]
    fn truncation(&self) -> Option<String> {
        self.inner.truncation.clone()
    }

    /// The header's maximum code width and block mode, once read (or as given).
    #[getter]
    fn header_params(&self) -> Option<(u32, bool)> {
        self.inner.header_params
    }

    #[getter]
    fn nine_bit_widens(&self) -> Option<bool> {
        self.inner.nine_bit_widens
    }

    /// The CLEAR codes the last call passed, as (input offset, output offset) pairs
    /// counted as `total_in` and `total_out` count: where a decoder made with this
    /// stream's `header_params` can start with a fresh dictionary. Each call reports
    /// only its own, so a caller that wants them all collects them.
    #[getter]
    fn clear_offsets(&self) -> Vec<(u64, u64)> {
        self.clear_offsets.clone()
    }

    /// Input bytes used: those passed in, less what the decoder holds undecoded.
    #[getter]
    fn total_in(&self) -> u64 {
        self.fed - self.inner.held_input() as u64
    }

    #[getter]
    fn total_out(&self) -> u64 {
        self.total_out
    }
}

struct PyInput<'a, 'py> {
    more: &'a Bound<'py, PyAny>,
}

impl lzx::Input for PyInput<'_, '_> {
    type Error = PyErr;
    fn more(&mut self) -> Result<Option<Vec<u8>>, PyErr> {
        let data = self.more.call0()?;
        if data.is_none() {
            return Ok(None);
        }
        if let Ok(b) = data.cast::<PyBytes>() {
            return Ok(Some(b.as_bytes().to_vec()));
        }
        Ok(Some(data.extract::<Vec<u8>>()?))
    }
}

#[pyclass(module = "archivey_codecs._codecs", name = "_LzxFrameDecoder")]
struct LzxDecoder {
    inner: lzx::LzxDecoder,
    /// The input callback; `None` once the garbage collector cleared it. The CAB
    /// reader passes a method of the object that holds this decoder, a cycle the
    /// collector must see (`__traverse__`) to free.
    more: Option<Py<PyAny>>,
}

fn cleared() -> PyErr {
    PyValueError::new_err("the decoder's input was cleared")
}

#[pymethods]
impl LzxDecoder {
    #[new]
    fn new(window_bits: u32, more: Py<PyAny>) -> PyResult<Self> {
        Ok(LzxDecoder {
            inner: lzx::LzxDecoder::new(window_bits).map_err(to_py0)?,
            more: Some(more),
        })
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        if let Some(more) = &self.more {
            visit.call(more)?;
        }
        Ok(())
    }

    fn __clear__(&mut self) {
        self.more = None;
    }

    fn decode_frame<'py>(
        &mut self,
        py: Python<'py>,
        frame_size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let more = self.more.as_ref().ok_or_else(cleared)?.bind(py).clone();
        let mut input = PyInput { more: &more };
        let out = self
            .inner
            .decode_frame(frame_size, &mut input)
            .map_err(to_py)?;
        Ok(PyBytes::new(py, &out))
    }
}

struct PyStreams<'a, 'py> {
    reads: &'a [Bound<'py, PyAny>; 4],
}

impl bcj2::Streams for PyStreams<'_, '_> {
    type Error = PyErr;
    fn read(&mut self, which: usize, n: usize) -> Result<Vec<u8>, PyErr> {
        let data = self.reads[which].call1((n,))?;
        if let Ok(b) = data.cast::<PyBytes>() {
            return Ok(b.as_bytes().to_vec());
        }
        data.extract::<Vec<u8>>()
    }
}

/// The BCJ2 decode loop. `reads` are the four streams' `read` methods: main, call,
/// jump, rc. On an error, the bytes decoded before it wait in `take_partial()`.
#[pyclass(module = "archivey_codecs._codecs", name = "_Bcj2Core")]
struct Bcj2Core {
    inner: bcj2::Bcj2,
    /// `None` once the garbage collector cleared them (see `LzxDecoder::more`).
    reads: Option<[Py<PyAny>; 4]>,
    partial: Vec<u8>,
}

impl Bcj2Core {
    fn streams<'py>(&self, py: Python<'py>) -> PyResult<[Bound<'py, PyAny>; 4]> {
        let r = self.reads.as_ref().ok_or_else(cleared)?;
        Ok([
            r[0].bind(py).clone(),
            r[1].bind(py).clone(),
            r[2].bind(py).clone(),
            r[3].bind(py).clone(),
        ])
    }
}

#[pymethods]
impl Bcj2Core {
    #[new]
    fn new(main: Py<PyAny>, call: Py<PyAny>, jump: Py<PyAny>, rc: Py<PyAny>) -> Self {
        Bcj2Core {
            inner: bcj2::Bcj2::new(),
            reads: Some([main, call, jump, rc]),
            partial: Vec::new(),
        }
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        for r in self.reads.iter().flatten() {
            visit.call(r)?;
        }
        Ok(())
    }

    fn __clear__(&mut self) {
        self.reads = None;
    }

    fn decode_block<'py>(&mut self, py: Python<'py>, left: u64) -> PyResult<Bound<'py, PyBytes>> {
        let reads = self.streams(py)?;
        let mut streams = PyStreams { reads: &reads };
        let mut out = Vec::new();
        match self.inner.decode_block(left, &mut out, &mut streams) {
            Ok(()) => Ok(PyBytes::new(py, &out)),
            Err(e) => {
                self.partial = out;
                Err(to_py(e))
            }
        }
    }

    fn take_partial<'py>(&mut self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &std::mem::take(&mut self.partial))
    }

    fn check_inputs_finished(&mut self, py: Python<'_>) -> PyResult<()> {
        let reads = self.streams(py)?;
        let mut streams = PyStreams { reads: &reads };
        self.inner
            .check_inputs_finished(&mut streams)
            .map_err(to_py)
    }
}

#[pymodule(gil_used = false)]
fn _codecs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    let kernels = PyDict::new(py);
    for (name, rev) in KERNELS {
        kernels.set_item(name, rev)?;
    }
    m.add("KERNELS", kernels)?;
    m.add("CodecError", py.get_type::<CodecError>())?;
    m.add("CorruptDataError", py.get_type::<CorruptDataError>())?;
    m.add("TruncatedDataError", py.get_type::<TruncatedDataError>())?;
    m.add(
        "UnsupportedDataError",
        py.get_type::<UnsupportedDataError>(),
    )?;
    m.add_function(wrap_pyfunction!(crc16_arc, m)?)?;
    m.add_class::<Crc16Arc>()?;
    m.add("lzo1x_decompress", wrap_pyfunction!(lzo1x_decompress, m)?)?;
    m.add("Arm64Decoder", py.get_type::<Arm64Decoder>())?;
    m.add("RiscvDecoder", py.get_type::<RiscvDecoder>())?;
    m.add("ZipCryptoDecryptor", py.get_type::<ZipCryptoDecryptor>())?;
    m.add("LzwDecompressor", py.get_type::<LzwDecompressor>())?;
    // The prototype's LZX and BCJ2 shapes, until their D3 shapes land.
    m.add("_LzxFrameDecoder", py.get_type::<LzxDecoder>())?;
    m.add("_Bcj2Core", py.get_type::<Bcj2Core>())?;
    Ok(())
}
