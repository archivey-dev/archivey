"""Cost of the binding per LZFSE run: in this process, and in a child over a pipe.

usage: python bench.py IMAGE.dmg

The child is one long-lived process, as archivey's decoder child is: the parent writes
each run's stored bytes with a length prefix and reads the decoded bytes back. Its
start cost (interpreter plus `import lzfse`) is timed apart. Each figure is the fastest
of three passes over the image's LZFSE runs.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import time

import common
import lzfse
from dmgproto import udif

CHILD = r"""
import struct, sys, lzfse
i, o = sys.stdin.buffer, sys.stdout.buffer
o.write(b"R"); o.flush()
while True:
    h = i.read(4)
    if len(h) < 4:
        break
    (n,) = struct.unpack("<I", h)
    out = lzfse.decompress(i.read(n))
    o.write(struct.pack("<I", len(out))); o.write(out); o.flush()
"""


def read_exact(f, n):
    b = f.read(n)
    if len(b) != n:
        raise EOFError
    return b


def main():
    path = sys.argv[1]
    img = udif.UdifImage(open(path, "rb"), os.path.getsize(path))  # noqa: SIM115  (the image keeps it)
    runs = []
    for r in img.runs:
        if r.kind == udif.LZFSE:
            img.f.seek(r.offset)
            runs.append((img.f.read(r.length), r.count * 512))
    total = sum(w for _, w in runs)

    def best(fn, passes=3):
        ts = []
        for _ in range(passes):
            t = time.perf_counter()
            fn()
            ts.append(time.perf_counter() - t)
        return min(ts)

    t_in = best(lambda: [lzfse.decompress(s) for s, _ in runs])
    t_walk = best(lambda: [common.walk_blocks(s) for s, _ in runs])

    starts = []
    for _ in range(5):
        t = time.perf_counter()
        p = subprocess.Popen(
            [sys.executable, "-c", CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        read_exact(p.stdout, 1)
        starts.append(time.perf_counter() - t)
        p.stdin.close()
        p.wait()
    p = subprocess.Popen(
        [sys.executable, "-c", CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    read_exact(p.stdout, 1)

    def via_child():
        for s, w in runs:
            p.stdin.write(struct.pack("<I", len(s)) + s)
            p.stdin.flush()
            (n,) = struct.unpack("<I", read_exact(p.stdout, 4))
            read_exact(p.stdout, n)

    t_child = best(via_child)
    p.stdin.close()
    p.wait()
    sample = runs[:20]
    t_proto = best(lambda: [common.proto_decode(s, w) for s, w in sample], passes=1)
    sample_bytes = sum(w for _, w in sample)
    n = len(runs)
    print(
        json.dumps(
            {
                "python": sys.version.split()[0],
                "runs": n,
                "decoded MiB": round(total / 2**20, 1),
                "mean run KiB": round(total / n / 1024),
                "in process: MB/s, ms per run": [
                    round(total / t_in / 1e6),
                    round(t_in / n * 1000, 2),
                ],
                "child over a pipe: MB/s, ms per run": [
                    round(total / t_child / 1e6),
                    round(t_child / n * 1000, 2),
                ],
                "child start ms (fastest of 5)": round(min(starts) * 1000, 1),
                "block walk ms per run": round(t_walk / n * 1000, 3),
                "prototype: MB/s on the first 20 runs": round(
                    sample_bytes / t_proto / 1e6, 1
                ),
            },
            indent=1,
        )
    )


if __name__ == "__main__":
    main()
