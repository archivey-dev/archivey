"""Prototype: 7z salvage.
(a) header readable: split each LZMA2 folder at dictionary-reset chunks and decode each part
    on its own; a file is kept when it lies inside decoded parts and its CRC matches.
(b) header lost (cut, damaged end): decode the packed area from offset 32 as raw LZMA2 streams;
    the output is unnamed (content without names)."""
import sys, lzma, zlib, struct
sys.path.insert(0, "/tmp/claude-0/sv/h"); from common import emit, save_blobs
path = sys.argv[1]; buf = open(path, "rb").read()
def chunks(p, end):
    """Walk LZMA2 chunk headers from p. Yield (pos, ctrl, unpacked, packed_total) until end marker/err."""
    out = []
    while p < end:
        c = buf[p]
        if c == 0: out.append((p, 0, 0, 1)); return out, True
        if c in (1, 2):
            u = struct.unpack(">H", buf[p + 1:p + 3])[0] + 1; out.append((p, c, u, 3 + u)); p += 3 + u
        elif c >= 0x80:
            u = ((c & 0x1F) << 16) + struct.unpack(">H", buf[p + 1:p + 3])[0] + 1
            k = struct.unpack(">H", buf[p + 3:p + 5])[0] + 1
            hl = 6 if c >= 0xC0 else 5
            out.append((p, c, u, hl + k)); p += hl + k
        else:
            return out, False
    return out, False
def is_dict_reset(c): return c == 1 or c >= 0xE0
def decode_part(start, endpos):
    d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 26}])
    try:
        return d.decompress(buf[start:endpos] + b"\0")
    except lzma.LZMAError:
        return None
ok = []; blobs = []; notes = {}
try:
    import py7zr
    a = py7zr.SevenZipFile(path)
    infos = [i for i in a.list() if not i.is_directory and i.uncompressed]
    ms = a.header.main_streams
    ss = ms.substreamsinfo
    sizes = (ss.unpacksizes if ss else None) or []; digests = (ss.digests if ss else None) or []
    per = (ss.num_unpackstreams_folders if ss else None) or [1] * len(ms.unpackinfo.folders)
    fi = 0; base = 32 + ms.packinfo.packpos
    for k, folder in enumerate(ms.unpackinfo.folders):
        p0 = base + ms.packinfo.packpositions[k]; p1 = p0 + ms.packinfo.packsizes[k]
        n = per[k]; fsizes = list(sizes[fi:fi + n]); fcrc = list(digests[fi:fi + n]) if digests else []
        if len(fsizes) < n: fsizes = [folder.get_unpack_size()]
        if len(fcrc) < n: fcrc = [folder.crc]
        fnames = [i.filename for i in infos[fi:fi + n]]; fi += n
        if folder.coders[0]["method"] != b"!":
            continue
        ch, clean = chunks(p0, p1)
        # a chain that ends (or breaks) before the folder's end: look for a dictionary-reset
        # chunk whose own chain lands exactly on the folder's end marker (p1 - 1)
        tail = None
        last = ch[-1][0] + ch[-1][3] if ch else p0
        if not (clean and last == p1):
            q = (ch[-1][0] + 1) if ch else p0 + 1
            while q < p1 - 6 and tail is None:
                c = buf[q]
                if c >= 0xE0 and buf[q + 5] <= 224:
                    ch2, ok2 = chunks(q, p1)
                    if ok2 and ch2[-1][0] == p1 - 1:
                        tail = ch2
                q += 1
        if tail:
            tot = sum(x[2] for x in tail); fu = sum(fsizes)
            ch = [x for x in ch if x[1] != 0]
            notes.setdefault("tail", []).append({"at": tail[0][0], "unpacked_from": fu - tot})
        parts = []; cur = None; uoff = 0
        for (p, c, u, t) in ch:
            if c == 0: break
            if is_dict_reset(c):
                if cur: parts.append(cur)
                cur = [p, p, uoff]
            if cur: cur[1] = p + t
            uoff += u
        if cur: parts.append(cur)
        if tail:
            # offsets counted back from the folder's end, so a false first chunk cannot shift them
            rem = sum(fsizes); offs = []
            for x in reversed(tail):
                rem -= x[2]; offs.append(rem)
            offs.reverse(); cur = None
            for (p, c, u, t), uo2 in zip(tail, offs):
                if c == 0: break
                if is_dict_reset(c):
                    if cur: parts.append(cur)
                    cur = [p, p, uo2]
                if cur: cur[1] = p + t
            if cur: parts.append(cur)
        known = {}  # unpacked offset -> bytes
        for (ps, pe, uo) in parts:
            data = decode_part(ps, pe)
            if data is not None: known[uo] = data
        # merge parts that decoded and touch each other
        merged = {}
        for uo in sorted(known):
            for mo in list(merged):
                if mo + len(merged[mo]) == uo:
                    merged[mo] += known[uo]; break
            else:
                merged[uo] = known[uo]
        known = merged
        notes[k] = {"chunks": len(ch), "chain_complete": clean, "parts": len(parts), "good_parts": len(known)}
        off = 0
        for name, sz, crc in zip(fnames, fsizes, fcrc):
            for uo, data in known.items():
                if uo <= off and off + sz <= uo + len(data):
                    b = data[off - uo: off - uo + sz]
                    if zlib.crc32(b) == crc: ok.append((name, b))
                    break
            off += sz
except Exception as e:
    notes["header_error"] = repr(e)[:120]
    # (b) no header: decode back-to-back LZMA2 streams from offset 32
    p = 32
    while p < len(buf) - 1:
        d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "dict_size": 1 << 26}])
        out = []
        try:
            for q in range(p, len(buf), 65536):
                out.append(d.decompress(buf[q:q + 65536]))
                if d.eof: break
        except lzma.LZMAError:
            pass
        data = b"".join(out)
        if len(data) == 0: break
        blobs.append(data)
        if not d.eof: break
        p = len(buf) - len(d.unused_data) if q + 65536 >= len(buf) else q + 65536 - len(d.unused_data)
        # unused_data is relative to the last fed piece
emit(ok, blobs, notes=notes, blobs_path=save_blobs('/tmp/claude-0/sv/blobs/' + path.replace('/', '_'), blobs) if blobs else None)
