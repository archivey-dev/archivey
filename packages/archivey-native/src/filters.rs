//! Branch-conversion filter decoders: ports of archivey's `arm64_decode`
//! (`arm64_filter.py`) and `riscv_decode` (`riscv_filter.py`), with the same
//! contract on how much of the input each call returns.

/// Decode the whole 4-byte words of `data`; `pc` is `data[0]`'s stream position.
pub fn arm64_decode(data: &[u8], pc: u64) -> Vec<u8> {
    let end = data.len() & !3;
    let mut out = data[..end].to_vec();
    let pc = pc as u32;
    for k in (0..end).step_by(4) {
        let top = out[k + 3];
        if top & 0xFC == 0x94 {
            let instr = u32::from_le_bytes([out[k], out[k + 1], out[k + 2], out[k + 3]]);
            let p = pc.wrapping_add(k as u32) >> 2;
            let v = 0x9400_0000 | (instr.wrapping_sub(p) & 0x03FF_FFFF);
            out[k..k + 4].copy_from_slice(&v.to_le_bytes());
        } else if top & 0x9F == 0x90 {
            let instr = u32::from_le_bytes([out[k], out[k + 1], out[k + 2], out[k + 3]]);
            let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001F_FFFC);
            if (src.wrapping_add(0x0002_0000)) & 0x001C_0000 == 0 {
                let dest = src.wrapping_sub(pc.wrapping_add(k as u32) >> 12);
                let v = (instr & 0x9000_001F)
                    | ((dest & 3) << 29)
                    | ((dest & 0x0003_FFFC) << 3)
                    | ((0u32.wrapping_sub(dest & 0x0002_0000)) & 0x00E0_0000);
                out[k..k + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
    }
    out
}

/// Decode what can be decoded of `data`; `pc` is `data[0]`'s stream position.
pub fn riscv_decode(data: &[u8], pc: u64) -> Vec<u8> {
    if data.len() < 8 {
        return Vec::new();
    }
    let last = data.len() - 8;
    let mut buf = data.to_vec();
    let pc = pc as u32;
    let mut resume = 0usize;
    let mut i = 0usize;
    let rd32 = |b: &[u8], i: usize| u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    while i <= last {
        let first = buf[i];
        if first == 0xEF {
            let b1 = buf[i + 1] as u32;
            if b1 & 0x0D != 0 {
                i += 2;
                continue;
            }
            let addr = ((((b1 & 0xF0) << 13) | ((buf[i + 2] as u32) << 9) | ((buf[i + 3] as u32) << 1))
                .wrapping_sub(pc))
            .wrapping_sub(i as u32);
            buf[i + 1] = ((b1 & 0x0F) | ((addr >> 8) & 0xF0)) as u8;
            buf[i + 2] = (((addr >> 16) & 0x0F) | ((addr >> 7) & 0x10) | ((addr << 4) & 0xE0)) as u8;
            buf[i + 3] = (((addr >> 4) & 0x7F) | ((addr >> 13) & 0x80)) as u8;
            resume = i + 4;
            i = resume;
        } else if first & 0x7F == 0x17 {
            let mut inst = rd32(&buf, i);
            let mut inst2: u32;
            if inst & 0xE80 != 0 {
                inst2 = rd32(&buf, i + 4);
                if ((inst << 8) ^ inst2.wrapping_sub(3)) & 0xF8003 != 0 {
                    resume = i + 6;
                    i = resume;
                    continue;
                }
                let addr = (inst & 0xFFFF_F000).wrapping_add(inst2 >> 20);
                inst = 0x17 | (2 << 7) | (inst2 << 12);
                inst2 = addr;
            } else {
                let rs1 = inst >> 27;
                if (inst.wrapping_sub(0x3117) << 18) >= (rs1 & 0x1D) {
                    resume = i + 4;
                    i = resume;
                    continue;
                }
                let be = u32::from_be_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
                let addr = be.wrapping_sub(pc.wrapping_add(i as u32));
                inst2 = (inst >> 12) | (addr << 20);
                inst = 0x17 | (rs1 << 7) | (addr.wrapping_add(0x800) & 0xFFFF_F000);
            }
            buf[i..i + 4].copy_from_slice(&inst.to_le_bytes());
            buf[i + 4..i + 8].copy_from_slice(&inst2.to_le_bytes());
            resume = i + 8;
            i = resume;
        } else {
            i += 2;
        }
    }
    let keep = resume.max((last / 2 + 1) * 2);
    buf.truncate(keep);
    buf
}
