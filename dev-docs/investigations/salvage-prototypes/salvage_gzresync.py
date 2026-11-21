"""Prototype: .tar.gz salvage = DEFLATE resync past damage, then TAR header scan on each segment."""
import sys, zlib, json, time
sys.path.insert(0, "/tmp/claude-0/sv/h"); from common import emit, tar_scan; from deflate_resync import *
buf = open(sys.argv[1], "rb").read()
segments = []; notes = []
# prefix decode
pos = 10
if len(buf) > 10 and buf[:2] == b"\x1f\x8b":
    flg = buf[3]
    if flg & 4: pos += 2 + int.from_bytes(buf[pos:pos+2], "little")
    if flg & 8: pos = buf.index(b"\0", pos) + 1
    if flg & 16: pos = buf.index(b"\0", pos) + 1
    if flg & 2: pos += 2
    d = zlib.decompressobj(-15); out = []; err_at = None
    for p in range(pos, len(buf), 4096):
        try:
            out.append(d.decompress(buf[p:p + 4096]))
        except zlib.error:
            err_at = p; break
        if d.eof: break
    pre = b"".join(out)
    segments.append((pre, b"\1" * len(pre)))
    nxt = err_at if err_at is not None else (None if d.eof else len(buf))
else:
    nxt = 0
t0 = time.time()
def validate(sh, j, k):
    src = sh[k][j:]
    d = zlib.decompressobj(-15, zdict=b"\0" * 32768); out = []; n = 0
    for p in range(0, len(src), 65536):
        try:
            o = d.decompress(src[p:p + 65536]); out.append(o)
        except zlib.error:
            break
        n = p + 65536
        if d.eof:
            used = len(src) - len(d.unused_data)
            return abs(len(src) - used - 8) <= 1   # genuine final block: trailer then EOF
        if n >= 1 << 20: return True
    data = b"".join(out)
    return bool(tar_scan(data[:1 << 20], aligned_only=False))  # domain check: a TAR header with a good checksum
while nxt is not None and nxt < len(buf) - 64 and time.time() - t0 < 60:
    B, k, sh, j, tried, dt = find_block_start(buf, nxt, validate=validate)
    notes.append({"search_from": nxt, "found": B, "bit": k, "tried": tried, "secs": round(dt, 2)})
    if B is None: break
    data, known, consumed, eof, err = decode_from(sh, j, k)
    segments.append((data, known))
    notes[-1].update(out=len(data), known_frac=round(sum(known) / max(1, len(known)), 3), eof=eof)
    if eof or consumed is None and err is None: break
    # continue after the next error: approximate by decoded input length via partial feed
    if err is not None:
        # find how much input decoded: re-feed to locate error point
        dd = zlib.decompressobj(-15, zdict=b"\0" * 32768); p = 0; src = sh[k][j:]
        while p < len(src):
            try: dd.decompress(src[p:p + 4096])
            except zlib.error: break
            p += 4096
        nxt = B + p + 1
    else:
        break
ok = []
for data, known in segments:
    ok += [(n, d) for n, d, o in tar_scan(data, known=known)]
emit(ok, notes=notes)
