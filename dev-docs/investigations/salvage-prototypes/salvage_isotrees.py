"""Prototype: ISO salvage = walk every directory tree the image holds (primary with Rock Ridge
names, Joliet) and the path tables, and take each file from whichever tree still reaches it.
ISO data has no checksums: the content is unverified either way."""
import sys, struct
sys.path.insert(0, "/tmp/claude-0/sv/h"); from common import emit
buf = open(sys.argv[1], "rb").read(); S = 2048
def recs(lba, size, joliet):
    out = []; p = lba * S; end = p + size
    while p < end and p < len(buf):
        L = buf[p]
        if L == 0:
            p = (p // S + 1) * S; continue
        r = buf[p:p + L]
        if len(r) < 34: break
        ext = struct.unpack_from("<I", r, 2)[0]; dl = struct.unpack_from("<I", r, 10)[0]
        if struct.unpack_from(">I", r, 6)[0] != ext or struct.unpack_from(">I", r, 14)[0] != dl:
            p += L; continue  # both-endian fields disagree: damaged record
        flags = r[25]; nl = r[32]; raw = r[33:33 + nl]
        if raw in (b"\0", b"\1"): p += L; continue
        if joliet: name = raw.decode("utf-16-be", "replace")
        else:
            name = raw.decode("latin-1").split(";")[0]
            su = r[33 + nl + ((nl + 1) % 2):]; i = 0
            while i + 4 <= len(su):
                sig, ln = su[i:i + 2], su[i + 2]
                if ln < 4: break
                if sig == b"NM": name = su[i + 5:i + ln].decode("utf-8", "replace")
                i += ln
        out.append((name, ext, dl, bool(flags & 2)))
        p += L
    return out
def walk(lba, size, joliet, prefix="", depth=0, seen=None):
    seen = seen if seen is not None else set()
    if depth > 32 or lba in seen: return []
    seen.add(lba); files = []
    for name, ext, dl, isdir in recs(lba, size, joliet):
        path = prefix + name
        if isdir: files += walk(ext, dl, joliet, path + "/", depth + 1, seen)
        elif ext * S + dl <= len(buf): files.append((path, buf[ext * S: ext * S + dl]))
    return files
found = {}; notes = []
for sec in range(16, 32):
    vd = buf[sec * S: sec * S + S]
    if len(vd) < 190 or vd[1:6] != b"CD001": continue
    t = vd[0]
    if t == 255: break
    if t not in (1, 2): continue
    joliet = t == 2 and vd[88:90] == b"%/"
    root = vd[156:190]
    ext = struct.unpack_from("<I", root, 2)[0]; dl = struct.unpack_from("<I", root, 10)[0]
    fl = walk(ext, dl, joliet)
    notes.append({"vd": sec, "joliet": joliet, "files": len(fl)})
    for n, d in fl: found.setdefault(n.lower(), (n, d))
emit(list(found.values()), notes=notes)
