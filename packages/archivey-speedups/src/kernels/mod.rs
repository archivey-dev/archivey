//! The kernels: pure Rust, no Python. Each mirrors one archivey Python decoder.

#![forbid(unsafe_code)]

pub mod bcj2;
pub mod crc16;
pub mod error;
pub mod filters;
pub mod lzfse;
pub mod lzo;
pub mod lzw;
pub mod lzx;
pub mod state;
pub mod zipcrypto;
