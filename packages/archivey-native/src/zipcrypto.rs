//! Traditional ZipCrypto (APPNOTE 6.1): a port of archivey's `ZipCryptoKeys`
//! (`internal/backends/zipcrypto.py`).

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC: [u32; 256] = crc_table();

#[derive(Clone, Copy, Debug)]
pub struct Keys {
    pub k0: u32,
    pub k1: u32,
    pub k2: u32,
}

impl Keys {
    pub fn new(password: &[u8]) -> Self {
        let mut k = Keys { k0: 0x1234_5678, k1: 0x2345_6789, k2: 0x3456_7890 };
        for &b in password {
            k.update(b);
        }
        k
    }

    #[inline(always)]
    fn update(&mut self, c: u8) {
        self.k0 = (self.k0 >> 8) ^ CRC[((self.k0 ^ c as u32) & 0xFF) as usize];
        self.k1 = self.k1.wrapping_add(self.k0 & 0xFF).wrapping_mul(134_775_813).wrapping_add(1);
        self.k2 = (self.k2 >> 8) ^ CRC[((self.k2 ^ (self.k1 >> 24)) & 0xFF) as usize];
    }

    /// Decrypt `data` in place and advance the state past it.
    pub fn decrypt_in_place(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            let t = (self.k2 | 2) & 0xFFFF;
            let c = *b ^ ((t.wrapping_mul(t ^ 1) >> 8) & 0xFF) as u8;
            *b = c;
            self.update(c);
        }
    }
}
