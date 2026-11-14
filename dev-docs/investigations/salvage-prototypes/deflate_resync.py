"""Find DEFLATE block starts past damage and decode from them with an unknown window.

Two decodes with different window fills (0x00 and 0xFF) mark which output bytes the
stream itself determines: a byte equal in both decodes did not come from the lost window."""
import zlib, time

def _shifted(buf, start):
    big = int.from_bytes(buf[start:], "little"); L = len(buf) - start
    return [(big >> k).to_bytes(L, "little") for k in range(8)]

def decode_from(sh, j, k, limit=1 << 30):
    """Decode raw deflate starting at bit k of byte j (relative). Returns (data, known_mask, consumed_bytes, eof)."""
    src = sh[k][j:]
    outs = []
    for fill in (b"\0", b"\xff"):
        d = zlib.decompressobj(-15, zdict=fill * 32768)
        try:
            o = d.decompress(src, limit); err = None
        except zlib.error as e:
            # decode as far as possible: binary search the input length that decodes cleanly
            o, err = _partial(src, fill, limit), e
            d = None
        outs.append((o, d, err))
    a, b = outs[0][0], outs[1][0]
    n = min(len(a), len(b)); a, b = a[:n], b[:n]
    known = bytes(1 if x == y else 0 for x, y in zip(a, b))
    d = outs[0][1]
    eof = bool(d and d.eof)
    consumed = (len(src) - len(d.unused_data)) if d else None
    return a, known, consumed, eof, outs[0][2]

def _partial(src, fill, limit):
    best = b""; lo, hi = 0, len(src)
    # feed in 4 KiB pieces until error
    d = zlib.decompressobj(-15, zdict=fill * 32768); out = []
    for p in range(0, len(src), 4096):
        try:
            out.append(d.decompress(src[p:p + 4096]))
        except zlib.error:
            break
        if d.eof: break
    return b"".join(out)

def find_block_start(buf, start, max_search=1 << 20, need=16384, deadline=30.0, validate=None):
    """First (byte, bit) at or after `start` where raw inflate runs `need` input bytes cleanly."""
    end = min(len(buf) - 1, start + max_search)
    sh = _shifted(buf, start)
    t0 = time.time(); tried = 0
    for j in range(0, end - start):
        for k in range(8):
            first = sh[k][j]
            btype = (first >> 1) & 3
            if btype == 3: continue
            tried += 1
            src = sh[k][j:j + need]
            d = zlib.decompressobj(-15, zdict=b"\0" * 32768)
            try:
                d.decompress(src, 1 << 22)
            except zlib.error:
                continue
            if d.eof:
                used = len(src) - len(d.unused_data)
                # a final block must end where the stream ends: the 8-byte gzip trailer, then EOF
                if abs((len(buf) - start - j) - used - 8) > 1:
                    continue
            if len(src) < need and not d.eof: continue
            if validate is not None and not validate(sh, j, k):
                continue
            return start + j, k, sh, j, tried, time.time() - t0
        if time.time() - t0 > deadline: break
    return None, None, None, None, tried, time.time() - t0
