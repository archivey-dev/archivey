//! Python bindings for archivey's optional Rust kernels.
//!
//! The kernels know nothing about archivey: they report `CorruptData`,
//! `TruncatedData` or `ValueError`, and archivey's shim (`archivey.internal.native`)
//! turns those into the exceptions the pure-Python decoders raise. Every entry point
//! that loops over caller data releases the GIL.

pub mod bcj2;
pub mod error;
pub mod filters;
pub mod lzo;
pub mod lzw;
pub mod lzx;
pub mod zipcrypto;

use error::DecodeError;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(_native, CorruptData, PyValueError, "The data is damaged.");
pyo3::create_exception!(_native, TruncatedData, PyValueError, "The data ends early.");
pyo3::create_exception!(_native, UnsupportedData, PyValueError, "The data uses a feature the kernel does not read.");

/// Bumped on any change to a signature or to what a kernel returns or raises.
/// archivey refuses a native package whose ABI_VERSION it does not know.
const ABI_VERSION: u32 = 1;

fn to_py(err: DecodeError<PyErr>) -> PyErr {
    match err {
        DecodeError::Corrupt(m) => CorruptData::new_err(m),
        DecodeError::Truncated(m) => TruncatedData::new_err(m),
        DecodeError::Unsupported(m) => UnsupportedData::new_err(m),
        DecodeError::Value(m) => PyValueError::new_err(m),
        DecodeError::Source(e) => e,
    }
}

fn to_py0(err: DecodeError) -> PyErr {
    match err {
        DecodeError::Corrupt(m) => CorruptData::new_err(m),
        DecodeError::Truncated(m) => TruncatedData::new_err(m),
        DecodeError::Unsupported(m) => UnsupportedData::new_err(m),
        DecodeError::Value(m) => PyValueError::new_err(m),
        DecodeError::Source(never) => match never {},
    }
}

#[pyfunction]
fn lzo1x_decompress<'py>(py: Python<'py>, data: &[u8], limit: usize) -> PyResult<Bound<'py, PyBytes>> {
    let out = py.detach(|| lzo::lzo1x_decompress(data, limit)).map_err(to_py0)?;
    Ok(PyBytes::new(py, &out))
}

#[pyfunction]
fn arm64_decode<'py>(py: Python<'py>, data: &[u8], pc: u64) -> Bound<'py, PyBytes> {
    let out = py.detach(|| filters::arm64_decode(data, pc));
    PyBytes::new(py, &out)
}

#[pyfunction]
fn riscv_decode<'py>(py: Python<'py>, data: &[u8], pc: u64) -> Bound<'py, PyBytes> {
    let out = py.detach(|| filters::riscv_decode(data, pc));
    PyBytes::new(py, &out)
}

#[pyclass(module = "archivey_native._native")]
#[derive(Clone)]
struct ZipCryptoKeys {
    keys: zipcrypto::Keys,
}

#[pymethods]
impl ZipCryptoKeys {
    #[new]
    fn new(password: &[u8]) -> Self {
        ZipCryptoKeys { keys: zipcrypto::Keys::new(password) }
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    fn decrypt<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
        let mut keys = self.keys;
        let out = PyBytes::new_with(py, data.len(), |buf| {
            buf.copy_from_slice(data);
            keys.decrypt_in_place(buf);
            Ok(())
        })?;
        self.keys = keys;
        Ok(out)
    }

    #[getter]
    fn k0(&self) -> u32 { self.keys.k0 }
    #[getter]
    fn k1(&self) -> u32 { self.keys.k1 }
    #[getter]
    fn k2(&self) -> u32 { self.keys.k2 }
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

#[pyclass(module = "archivey_native._native")]
struct LzxDecoder {
    inner: lzx::LzxDecoder,
    more: Py<PyAny>,
}

#[pymethods]
impl LzxDecoder {
    #[new]
    fn new(window_bits: u32, more: Py<PyAny>) -> PyResult<Self> {
        Ok(LzxDecoder { inner: lzx::LzxDecoder::new(window_bits).map_err(to_py0)?, more })
    }

    fn decode_frame<'py>(&mut self, py: Python<'py>, frame_size: usize) -> PyResult<Bound<'py, PyBytes>> {
        let more = self.more.bind(py).clone();
        let mut input = PyInput { more: &more };
        let out = self.inner.decode_frame(frame_size, &mut input).map_err(to_py)?;
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
#[pyclass(module = "archivey_native._native")]
struct Bcj2Core {
    inner: bcj2::Bcj2,
    reads: [Py<PyAny>; 4],
    partial: Vec<u8>,
}

#[pymethods]
impl Bcj2Core {
    #[new]
    fn new(main: Py<PyAny>, call: Py<PyAny>, jump: Py<PyAny>, rc: Py<PyAny>) -> Self {
        Bcj2Core { inner: bcj2::Bcj2::new(), reads: [main, call, jump, rc], partial: Vec::new() }
    }

    fn decode_block<'py>(&mut self, py: Python<'py>, left: u64) -> PyResult<Bound<'py, PyBytes>> {
        let reads = [
            self.reads[0].bind(py).clone(),
            self.reads[1].bind(py).clone(),
            self.reads[2].bind(py).clone(),
            self.reads[3].bind(py).clone(),
        ];
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
        let reads = [
            self.reads[0].bind(py).clone(),
            self.reads[1].bind(py).clone(),
            self.reads[2].bind(py).clone(),
            self.reads[3].bind(py).clone(),
        ];
        let mut streams = PyStreams { reads: &reads };
        self.inner.check_inputs_finished(&mut streams).map_err(to_py)
    }
}

type LzwOut<'py> = (Bound<'py, PyBytes>, Vec<(i64, i64)>);

#[pyclass(module = "archivey_native._native")]
struct LzwState {
    inner: lzw::LzwState,
}

#[pymethods]
impl LzwState {
    #[new]
    #[pyo3(signature = (*, max_width=None, block_mode=None, nine_bit_widens=None))]
    fn new(max_width: Option<u32>, block_mode: Option<bool>, nine_bit_widens: Option<bool>) -> Self {
        LzwState { inner: lzw::LzwState::new(max_width, block_mode, nine_bit_widens) }
    }

    #[pyo3(signature = (data, max_length=-1))]
    fn feed<'py>(&mut self, py: Python<'py>, data: &[u8], max_length: i64) -> PyResult<LzwOut<'py>> {
        let inner = &mut self.inner;
        let (out, units) = py.detach(|| inner.feed(data, max_length)).map_err(to_py0)?;
        Ok((PyBytes::new(py, &out), units))
    }

    fn flush<'py>(&mut self, py: Python<'py>) -> PyResult<LzwOut<'py>> {
        let (out, units) = self.inner.flush().map_err(to_py0)?;
        Ok((PyBytes::new(py, &out), units))
    }

    fn is_finished(&self) -> bool { self.inner.is_finished() }
    #[getter]
    fn needs_input(&self) -> bool { self.inner.needs_input() }
    #[getter]
    fn header_params(&self) -> Option<(u32, bool)> { self.inner.header_params }
    #[getter]
    fn nine_bit_widens(&self) -> Option<bool> { self.inner.nine_bit_widens }
    #[getter]
    fn truncated(&self) -> bool { self.inner.truncation.is_some() }
    #[getter]
    fn truncation(&self) -> Option<String> { self.inner.truncation.clone() }
}

#[pymodule(gil_used = false)]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("ABI_VERSION", ABI_VERSION)?;
    m.add("CorruptData", m.py().get_type::<CorruptData>())?;
    m.add("TruncatedData", m.py().get_type::<TruncatedData>())?;
    m.add("UnsupportedData", m.py().get_type::<UnsupportedData>())?;
    m.add_function(wrap_pyfunction!(lzo1x_decompress, m)?)?;
    m.add_function(wrap_pyfunction!(arm64_decode, m)?)?;
    m.add_function(wrap_pyfunction!(riscv_decode, m)?)?;
    m.add_class::<ZipCryptoKeys>()?;
    m.add_class::<LzxDecoder>()?;
    m.add_class::<LzwState>()?;
    m.add_class::<Bcj2Core>()?;
    Ok(())
}
