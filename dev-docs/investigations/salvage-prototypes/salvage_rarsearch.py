"""Prototype: RAR5 salvage = search every byte for a header whose CRC32 checks; stored members
are read directly and checked by their data CRC (compressed ones would go through unrar on a
synthetic archive, as archivey already does)."""
import sys, zlib, struct
sys.path.insert(0, "/tmp/claude-0/sv/h"); from common import emit
buf = open(sys.argv[1], "rb").read()
def vint(p):
    v = s = 0
    for i in range(10):
        x = buf[p + i]; v |= (x & 0x7F) << s; s += 7
        if not x & 0x80: return v, p + i + 1
    raise ValueError
ok = []; p = 0; found = 0; scanned = 0; compressed = 0
while p < len(buf) - 7:
    try:
        hsize, q = vint(p + 4)
        if not 2 <= hsize <= 2 * 1024 * 1024 or q + hsize > len(buf): raise ValueError
        # cheap plausibility first: a known header type and a flags byte with no unknown bits
        if not 1 <= buf[q] <= 5 or buf[q + 1] & 0xF0: raise ValueError
        if zlib.crc32(buf[p + 4:q + hsize]) != struct.unpack_from("<I", buf, p)[0]: raise ValueError
    except (ValueError, IndexError, struct.error):
        p += 1; scanned += 1; continue
    found += 1
    end = q + hsize
    htype, r = vint(q); hflags, r = vint(r)
    if hflags & 1: _, r = vint(r)
    dsize = 0
    if hflags & 2: dsize, r = vint(r)
    if htype == 2:
        ff, r = vint(r); usize, r = vint(r); attr, r = vint(r)
        if ff & 2: r += 4
        dcrc = None
        if ff & 4: dcrc = struct.unpack_from("<I", buf, r)[0]; r += 4
        ci, r = vint(r); host, r = vint(r); nl, r = vint(r); name = buf[r:r + nl].decode("utf-8", "replace")
        method = (ci >> 7) & 7
        data = buf[end:end + dsize]
        if method == 0 and len(data) == dsize and (dcrc is None or zlib.crc32(data) == dcrc) and not ff & 1:
            ok.append((name, data))
        elif method != 0: compressed += 1
    p = end + dsize
emit(ok, notes={"headers": found, "compressed_skipped": compressed})
