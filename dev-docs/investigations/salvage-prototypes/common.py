import hashlib, json, sys, struct, zlib
def emit(ok, unnamed=(), notes=None, **kw):
    print(json.dumps({"ok": [[n, hashlib.sha1(d).hexdigest()] for n, d in ok],
                      "unnamed": [hashlib.sha1(b).hexdigest() for b in unnamed],
                      "unnamed_blobs_path": kw.get("blobs_path"), "notes": notes}))
def save_blobs(path, blobs):
    import pickle
    p = path + ".blobs.pkl"
    with open(p, "wb") as f: pickle.dump(list(blobs), f)
    return p

def tar_scan(buf, known=None, aligned_only=False):
    """Find TAR headers in buf: every 512-aligned block, plus any byte where 'ustar' sits at +257.
    known: optional bytearray mask (1 = byte is determined); members touching unknown bytes are dropped.
    Returns [(name, data, offset)]."""
    out = []
    cands = set(range(0, len(buf) - 511, 512))
    if not aligned_only:
        i = buf.find(b"ustar", 257)
        while i != -1:
            cands.add(i - 257); i = buf.find(b"ustar", i + 1)
    longname = None
    claimed_end = 0
    for off in sorted(cands):
        if off < claimed_end or off < 0: continue
        h = buf[off:off + 512]
        if len(h) < 512 or h == b"\0" * 512: continue
        try:
            chk = int(h[148:156].split(b"\0")[0].strip() or b"-1", 8)
        except ValueError:
            continue
        s = sum(h[:148]) + 256 + sum(h[156:])
        if chk != s: continue
        try:
            size = int(h[124:136].split(b"\0")[0].strip() or b"0", 8)
        except ValueError:
            continue
        typ = h[156:157]
        name = h[:100].split(b"\0")[0]
        if h[257:262] == b"ustar" and h[345:500].split(b"\0")[0]:
            name = h[345:500].split(b"\0")[0] + b"/" + name
        dstart = off + 512; dend = dstart + size
        nxt = dstart + (size + 511) // 512 * 512
        if typ == b"L":
            longname = buf[dstart:dend].split(b"\0")[0]; claimed_end = nxt; continue
        if typ in (b"x", b"g"):
            # pax: take path= if present
            rec = buf[dstart:dend]
            for line in rec.split(b"\n"):
                if b" path=" in line: longname = line.split(b" path=", 1)[1]
            claimed_end = nxt; continue
        if longname is not None: name, longname = longname, None
        if typ in (b"0", b"\0", b"7") and dend <= len(buf):
            if known is not None and not all(known[dstart:dend]):
                continue
            out.append((name.decode("utf-8", "replace"), bytes(buf[dstart:dend]), off))
            claimed_end = nxt
        elif typ in (b"5", b"1", b"2"):
            claimed_end = nxt
    return out
