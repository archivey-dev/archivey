//! CRC-16/ARC (polynomial 0x8005, reflected, initial value 0, no final XOR), as LHA
//! and ARJ check data and headers: a port of archivey's `lha_reader.crc16`.

const fn table() -> [u16; 256] {
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u16;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xA001
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static TABLE: [u16; 256] = table();

/// The CRC of `data`, continuing from `crc` (0 to start).
pub fn crc16_arc(data: &[u8], crc: u16) -> u16 {
    let mut crc = crc;
    for &b in data {
        crc = (crc >> 8) ^ TABLE[((crc ^ u16::from(b)) & 0xFF) as usize];
    }
    crc
}

#[cfg(test)]
mod tests {
    #[test]
    fn check_value() {
        // The CRC catalogue's check value for CRC-16/ARC.
        assert_eq!(super::crc16_arc(b"123456789", 0), 0xBB3D);
    }
}
