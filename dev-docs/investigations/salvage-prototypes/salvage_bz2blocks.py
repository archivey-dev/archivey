"""Prototype: .tar.bz2 salvage = bzip2recover-style block split (each block has its own CRC), then TAR scan."""
import sys, bz2
sys.path.insert(0, "/tmp/claude-0/sv/h"); from common import emit, tar_scan
buf = open(sys.argv[1], "rb").read()
BLK, EOS = 0x314159265359, 0x177245385090
N = len(buf) * 8
big = int.from_bytes(buf, "big")
def bits(a, n):  # n bits starting at bit a (MSB-first)
    return (big >> (N - a - n)) & ((1 << n) - 1)
pos = []
for r in range(8):
    sh = ((big << r) & ((1 << N) - 1)).to_bytes(len(buf), "big")
    for magic, isb in ((BLK, True), (EOS, False)):
        mb = magic.to_bytes(6, "big"); i = sh.find(mb)
        while i != -1:
            pos.append((i * 8 + r, isb)); i = sh.find(mb, i + 1)
pos.sort()
blocks = []
for i, (a, isblk) in enumerate(pos):
    if not isblk: continue
    end = pos[i + 1][0] if i + 1 < len(pos) else N
    nb = end - a
    crc = bits(a + 48, 32)
    payload = (big >> (N - end)) & ((1 << nb) - 1)
    total = (payload << 48 | EOS) << 32 | crc
    tb = nb + 48 + 32
    pad = (-tb) % 8
    data = b"BZh9" + (total << pad).to_bytes((tb + pad) // 8, "big")
    try:
        out = bz2.decompress(data); blocks.append((a, out, True))
    except (OSError, ValueError, EOFError):
        blocks.append((a, b"", False))
ok = []; notes = [{"block_bit": a, "out": len(o), "good": g} for a, o, g in blocks]
# contiguous runs of good blocks form segments with known alignment only from the start
seg = b""; segs = []
for idx, (a, o, g) in enumerate(blocks):
    if g: seg += o
    else:
        if seg: segs.append(seg)
        seg = b""
if seg: segs.append(seg)
for s in segs:
    ok += [(n, d) for n, d, o in tar_scan(s)]
emit(ok, notes=notes)
