//! Saved decoder states: little-endian fields, read back with every length checked, so
//! a cut-off or padded state is refused as damage rather than misread.

use crate::kernels::error::{DecodeError, Result};

pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// A byte string with its length in front (u32).
pub fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    kernel: &'a str,
}

impl<'a> Reader<'a> {
    pub fn new(kernel: &'a str, data: &'a [u8], pos: usize) -> Self {
        Reader { data, pos, kernel }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn cut<T>(&self) -> Result<T> {
        Err(DecodeError::Corrupt(format!(
            "the {} state is cut off",
            self.kernel
        )))
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        match self.data.get(self.pos..self.pos.saturating_add(n)) {
            Some(got) => {
                self.pos += n;
                Ok(got)
            }
            None => self.cut(),
        }
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            v => self.bad(format!("a flag of {v}")),
        }
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }

    /// A byte string written by `put_bytes`, at most `max` bytes long.
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return self.bad(format!("a field of {n} bytes, more than {max}"));
        }
        self.take(n)
    }

    /// Refuse a state whose contents a decoder could not have saved.
    pub fn bad<T>(&self, what: impl AsRef<str>) -> Result<T> {
        Err(DecodeError::Corrupt(format!(
            "the {} state holds {}",
            self.kernel,
            what.as_ref()
        )))
    }

    pub fn finish(&self) -> Result<()> {
        if self.pos != self.data.len() {
            return Err(DecodeError::Corrupt(format!(
                "{} bytes follow the {} state",
                self.data.len() - self.pos,
                self.kernel
            )));
        }
        Ok(())
    }
}
