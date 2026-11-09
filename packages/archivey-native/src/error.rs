//! The error kinds a kernel reports. The Python shim in archivey turns each into the
//! archivey exception the pure-Python decoder raises, with the same message.

#[derive(Debug)]
pub enum DecodeError<E = std::convert::Infallible> {
    /// The data is damaged (archivey: `CorruptionError`, or the codec's own error).
    Corrupt(String),
    /// The data ends early (archivey: `TruncatedError`).
    Truncated(String),
    /// The data uses a feature archivey does not read (archivey:
    /// `UnsupportedFeatureError`).
    Unsupported(String),
    /// The caller passed a bad argument (Python `ValueError`).
    Value(String),
    /// The input callback failed; the error passes through unchanged.
    Source(E),
}

pub type Result<T, E = std::convert::Infallible> = std::result::Result<T, DecodeError<E>>;

pub fn corrupt<T, E>(msg: impl Into<String>) -> Result<T, E> {
    Err(DecodeError::Corrupt(msg.into()))
}

pub fn truncated<T, E>(msg: impl Into<String>) -> Result<T, E> {
    Err(DecodeError::Truncated(msg.into()))
}
