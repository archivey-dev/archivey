"""Prototype: .tar.xz salvage = decode each xz block on its own (index or header-CRC scan), then TAR scan."""
import sys, lzma, struct, zlib
sys.path.insert(0, "/tmp/claude-0/sv/h"); from common import emit, tar_scan
buf = open(sys.argv[1], "rb").read()
T = []
for i in range(256):
    c = i
    for _ in range(8): c = (c >> 1) ^ (0xC96C5795D7870F42 if c & 1 else 0)
    T.append(c)
def crc64(b):
    c = 0xFFFFFFFFFFFFFFFF
    for x in b: c = T[(c ^ x) & 0xFF] ^ (c >> 8)
    return c ^ 0xFFFFFFFFFFFFFFFF
def vli(b, p):
    v = 0; s = 0
    while True:
        x = b[p]; p += 1; v |= (x & 0x7F) << s; s += 7
        if not x & 0x80: return v, p
check_type = buf[7] & 0x0F if len(buf) > 12 and buf[:6] == b"\xfd7zXZ\0" else 4
csize = {0: 0, 1: 4, 4: 8, 10: 32}.get(check_type, 8)
def block_header(p):
    hs = (buf[p] + 1) * 4
    if buf[p] == 0 or p + hs > len(buf): return None
    h = buf[p:p + hs]
    if zlib.crc32(h[:-4]) != struct.unpack("<I", h[-4:])[0]: return None
    flags = h[1]; q = 2; csz = usz = None
    if flags & 0x40: csz, q = vli(h, q)
    if flags & 0x80: usz, q = vli(h, q)
    filters = []
    for _ in range((flags & 3) + 1):
        fid, q = vli(h, q); psz, q = vli(h, q); props = h[q:q + psz]; q += psz
        if fid == 0x21:
            d = props[0]; dict_size = (2 | (d & 1)) << (d // 2 + 11)
            filters.append({"id": lzma.FILTER_LZMA2, "dict_size": dict_size})
        else:
            return None
    return hs, csz, usz, filters
# candidate block starts: 4-aligned offsets whose header CRC32 checks
cands = [p for p in range(12, len(buf) - 8, 4) if buf[p] and block_header(p)]
out_blocks = []; claimed = 0
for p in cands:
    if p < claimed: continue
    hs, csz, usz, filters = block_header(p)
    d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters)
    try:
        data = d.decompress(buf[p + hs:])
    except lzma.LZMAError:
        out_blocks.append((p, None)); continue
    if not d.eof:
        out_blocks.append((p, None)); continue
    used = len(buf) - p - hs - len(d.unused_data)
    q = p + hs + used; q += (-q) % 4
    chk = buf[q:q + csize]
    good = (check_type == 4 and struct.unpack("<Q", chk)[0] == crc64(data)) or (check_type == 1 and struct.unpack("<I", chk)[0] == zlib.crc32(data))
    out_blocks.append((p, data if good else None)); claimed = q + csize
ok = []; seg = b""; segs = []
for p, data in out_blocks:
    if data is None:
        if seg: segs.append(seg)
        seg = b""
    else: seg += data
if seg: segs.append(seg)
for s in segs: ok += [(n, d) for n, d, o in tar_scan(s)]
emit(ok, notes=[{"block": p, "good": d is not None, "out": len(d or b"")} for p, d in out_blocks])
