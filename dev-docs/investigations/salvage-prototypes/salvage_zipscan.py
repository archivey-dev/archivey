"""Prototype: ZIP salvage by scanning for local file headers; each member's data checked by its CRC."""
import sys, struct, zlib
sys.path.insert(0, "/tmp/claude-0/sv/h"); from common import emit
buf = open(sys.argv[1], "rb").read()
ok = []; i = buf.find(b"PK\3\4"); claimed = 0; fp = 0
while i != -1:
    if i < claimed: i = buf.find(b"PK\3\4", i + 1); continue
    try:
        ver, flag, meth, t, d, crc, csize, usize, nl, xl = struct.unpack_from("<HHHHHIIIHH", buf, i + 4)
    except struct.error:
        break
    name = buf[i + 30:i + 30 + nl]; ds = i + 30 + nl + xl
    good = False
    if meth in (0, 8) and 0 < nl < 1024:
        try:
            if meth == 8:
                do = zlib.decompressobj(-15); data = do.decompress(buf[ds:ds + (csize if not flag & 8 else len(buf))], 1 << 28)
                if do.eof:
                    used = (csize if not flag & 8 else len(buf)) - len(do.unused_data) if not flag & 8 else len(buf) - ds - len(do.unused_data)
                    end = ds + used
                    if flag & 8:  # data descriptor
                        p = end + (4 if buf[end:end + 4] == b"PK\7\x08" else 0)
                        crc, csize, usize = struct.unpack_from("<III", buf, p); end = p + 12
                    good = zlib.crc32(data) == crc
            else:
                if flag & 8:
                    j = buf.find(b"PK\7\x08", ds)
                    while j != -1:
                        c2, cs2, us2 = struct.unpack_from("<III", buf, j + 4)
                        if cs2 == j - ds and zlib.crc32(buf[ds:j]) == c2:
                            crc, csize = c2, cs2; break
                        j = buf.find(b"PK\7\x08", j + 1)
                data = buf[ds:ds + csize]; end = ds + csize
                good = len(data) == csize and zlib.crc32(data) == crc
        except (zlib.error, struct.error):
            good = False
    if good:
        ok.append((name.decode("utf-8", "replace"), data)); claimed = end; fp += 0
        i = buf.find(b"PK\3\4", end)
    else:
        i = buf.find(b"PK\3\4", i + 1)
emit(ok)
