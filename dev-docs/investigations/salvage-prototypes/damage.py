"""Make deterministic damaged copies of each archive in a/ into d/<archive>/<case>."""
import os, random, sys, shutil
A, D = sys.argv[1], sys.argv[2]
shutil.rmtree(D, ignore_errors=True)
for fn in sorted(os.listdir(A)):
    data = open(os.path.join(A, fn), "rb").read()
    n = len(data)
    rnd = random.Random(fn)
    cases = {}
    for p in (25, 50, 75, 95):
        cases[f"cut{p:02d}"] = data[: n * p // 100]
    cases["cut_tail100"] = data[: n - 100]
    for p in (10, 30, 50, 70, 90):
        off = (n * p // 100) // 4096 * 4096
        cases[f"zero4k_{p:02d}"] = data[:off] + b"\0" * 4096 + data[off + 4096:]
    for i in range(8):
        off = rnd.randrange(n)
        b = bytearray(data); b[off] ^= 0x55
        cases[f"flip{i}_{off}"] = bytes(b)
    cases["head4k_lost"] = data[4096:]
    # a whole 64 KiB run lost from the middle (bytes deleted, not zeroed)
    mid = n // 2
    cases["gap64k_mid"] = data[:mid] + data[mid + 65536:]
    ext = fn[fn.index("."):]
    for c, b in cases.items():
        os.makedirs(os.path.join(D, fn), exist_ok=True)
        open(os.path.join(D, fn, c + ext), "wb").write(b)
print("ok")
