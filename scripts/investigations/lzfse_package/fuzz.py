"""Differential fuzz: the `lzfse` binding against the prototype, in child processes.

usage: python fuzz.py CASES [SHARDS] [OUT.json]

Seeds are the binding's own encoder output for varied inputs (bvx-, bvxn and bvx2
blocks; one or several blocks). Each case mutates a seed, deterministically from its
index. A case runs in a shard process with a 1 GiB address-space limit; the parent
restarts a shard that dies or stops making progress for 30 s, and records the case as a
crash or a hang. Per case it records:

- the block walk (`common.walk_blocks`): refused, or the declared total;
- the prototype, with the seed's true size as the limit;
- the binding called directly on every input (the C decoder sees all of them);
- the capped binding (`common.binding_capped`).

The verdict compared is the reader's: the exact bytes of the expected size, or a
refusal.
"""

from __future__ import annotations

import json
import os
import random
import struct
import subprocess
import sys
import time
from pathlib import Path

import common

HERE = os.path.dirname(os.path.abspath(__file__))


def seeds():
    import lzfse

    rnd = random.Random(7)
    words = [
        bytes(rnd.choice(b"abcdefghijklmnop \n") for _ in range(rnd.randint(1, 9)))
        for _ in range(80)
    ]
    out = []
    for n in (0, 1, 7, 100, 1000, 3000, 4095, 4096, 5000, 20000, 65536):
        text = b"".join(rnd.choice(words) for _ in range(n))[:n]
        rand = rnd.randbytes(n)
        mixed = bytes(b if i % 7 else 0 for i, b in enumerate(text))
        zeros = bytes(n)
        for data in (text, rand, mixed, zeros):
            out.append((data, lzfse.compress(data)))
    # several blocks: concatenate two streams' blocks
    a, b = out[-4], out[-3]
    data = a[0] + b[0]
    out.append((data, a[1][:-4] + b[1]))
    return out


def mutate(rnd, seed_list):
    data, z = rnd.choice(seed_list)
    z = bytearray(z)
    op = rnd.randrange(8)
    if op == 0 and z:
        for _ in range(rnd.randint(1, 4)):
            i = rnd.randrange(len(z))
            z[i] ^= 1 << rnd.randrange(8)
    elif op == 1 and z:
        for _ in range(rnd.randint(1, 4)):
            z[rnd.randrange(len(z))] = rnd.randrange(256)
    elif op == 2:
        z = z[: rnd.randrange(len(z) + 1)]
    elif op == 3:
        z += rnd.randbytes(rnd.randint(1, 64))
    elif op == 4:
        other = rnd.choice(seed_list)[1]
        i, j = rnd.randrange(len(z) + 1), rnd.randrange(len(other) + 1)
        z = z[:i] + other[j:]
    elif op == 5 and len(z) >= 8:
        # a size field in the first header: n_raw, or the next u32
        off = rnd.choice((4, 8)) if len(z) >= 12 else 4
        (v,) = struct.unpack_from("<I", z, off)
        v = max(
            0,
            min(
                0xFFFFFFFF,
                v + rnd.choice((-1, 1, -16, 16, 1 << 20, -(1 << 20), 1 << 31)),
            ),
        )
        struct.pack_into("<I", z, off, v)
    elif op == 6 and len(z) >= 32 and z[:4] == b"bvx2":
        # one bit of the packed v2 fields (counts, states, header size)
        i = 12 + rnd.randrange(24)
        z[i] ^= 1 << rnd.randrange(8)
    else:
        for _ in range(rnd.randint(5, 40)):
            z[rnd.randrange(len(z))] = rnd.randrange(256) if z else 0
    limit = (
        len(data)
        if rnd.random() < 0.9
        else max(0, len(data) + rnd.choice((-1, 1, 4096)))
    )
    return bytes(z), limit


def verdict(fn):
    try:
        return ("bytes", fn())
    except MemoryError:
        return ("MemoryError", None)
    except Exception as e:  # noqa: BLE001
        return (type(e).__name__, None)


def run_shard(start, count, seed, progress_path, out_path):
    import lzfse

    common.set_memory_limit(1 << 30)
    seed_list = seeds()
    with open(out_path, "a") as out:
        for k in range(start, start + count):
            tmp = progress_path + ".tmp"
            with open(tmp, "w") as p:
                p.write(str(k))
            os.replace(tmp, progress_path)  # the parent never reads a half-written file
            rnd = random.Random(f"{seed}:{k}")
            src, limit = mutate(rnd, seed_list)
            walk = verdict(lambda s=src: common.walk_blocks(s)[0])
            proto = verdict(lambda s=src, n=limit: common.proto_decode(s, n))
            direct = verdict(lambda s=src: lzfse.decompress(s))
            capped = verdict(lambda s=src, n=limit: common.binding_capped(lzfse, s, n))

            def reader(v, n=limit):
                return v[1] if v[0] == "bytes" and len(v[1]) == n else None

            rec = {
                "k": k,
                "walk": walk[0] if walk[0] != "bytes" else "ok",
                "over": walk[0] == "bytes" and walk[1] > limit,
                "proto": proto[0],
                "direct": direct[0],
                "capped": capped[0],
                "agree": reader(proto) == reader(capped),
                "direct_over": direct[0] == "bytes" and len(direct[1]) > limit,
            }
            interesting = (
                not rec["agree"]
                or capped[0] in ("MemoryError", "AssertionError")
                or proto[0] not in ("bytes", "LzfseError")
            )
            if interesting:
                rec["src"] = src.hex()
                rec["limit"] = limit
                rec["proto_len"] = len(proto[1]) if proto[0] == "bytes" else None
                rec["capped_len"] = len(capped[1]) if capped[0] == "bytes" else None
            out.write(json.dumps(rec) + "\n")
    with open(progress_path + ".tmp", "w") as p:
        p.write("done")
    os.replace(progress_path + ".tmp", progress_path)


def main():
    if sys.argv[1] == "--shard":
        _, _, start, count, seed, prog, out = sys.argv
        run_shard(int(start), int(count), seed, prog, out)
        return
    cases = int(sys.argv[1])
    shards = int(sys.argv[2]) if len(sys.argv) > 2 else os.cpu_count() or 1
    report = (
        sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "results", "fuzz.json")
    )
    work = os.path.join(HERE, "results", "fuzz-work")
    os.makedirs(work, exist_ok=True)
    seed = "a0"
    per = (cases + shards - 1) // shards
    todo = {
        i: (i * per, min(per, cases - i * per))
        for i in range(shards)
        if cases - i * per > 0
    }
    events = []
    procs = {}

    def launch(i, start, count):
        prog = os.path.join(work, f"p{i}")
        Path(prog).write_text(str(start))
        procs[i] = (
            subprocess.Popen(
                [
                    sys.executable,
                    __file__,
                    "--shard",
                    str(start),
                    str(count),
                    seed,
                    prog,
                    os.path.join(work, f"o{i}.jsonl"),
                ]
            ),
            start + count,
            time.time(),
            str(start),
        )

    for f in os.listdir(work):
        os.remove(os.path.join(work, f))
    for i, (s, c) in todo.items():
        launch(i, s, c)
    t0 = time.time()
    while procs:
        time.sleep(1)
        for i, (p, end, last_t, last_k) in list(procs.items()):
            prog = Path(work, f"p{i}").read_text()
            if prog != last_k:
                procs[i] = (p, end, time.time(), prog)
                last_t = time.time()
            rc = p.poll()
            if rc is not None and prog == "done":
                del procs[i]
                continue
            if rc is not None or time.time() - last_t > 30:
                if rc is None:
                    p.kill()
                    p.wait()
                kind = "hang" if rc is None else f"crash (exit {rc})"
                events.append({"case": int(prog), "kind": kind})
                del procs[i]
                nxt = int(prog) + 1
                if nxt < end:
                    launch(i, nxt, end - nxt)
    elapsed = time.time() - t0
    recs = []
    for f in sorted(os.listdir(work)):
        if f.endswith(".jsonl"):
            recs += [
                json.loads(line) for line in Path(work, f).read_text().splitlines()
            ]
    summary = {
        "cases": len(recs),
        "seconds": round(elapsed),
        "crashes and hangs": events,
    }
    from collections import Counter

    summary["walk"] = Counter(r["walk"] for r in recs)
    summary["walk over limit"] = sum(r["over"] for r in recs)
    summary["prototype"] = Counter(r["proto"] for r in recs)
    summary["binding, direct"] = Counter(r["direct"] for r in recs)
    summary["binding, direct, output over limit"] = sum(r["direct_over"] for r in recs)
    summary["binding, capped"] = Counter(r["capped"] for r in recs)
    summary["reader verdicts agree"] = sum(r["agree"] for r in recs)
    dis = [r for r in recs if not r["agree"]]
    summary["disagreements"] = len(dis)
    other = [r for r in recs if r["agree"] and "src" in r]
    os.makedirs(os.path.dirname(report), exist_ok=True)

    def short(rs):
        return [{k: v for k, v in r.items() if k != "src"} for r in rs]

    Path(report).write_text(
        json.dumps(
            {
                "summary": summary,
                "disagreements": short(dis[:40]),
                "other repros": short(other[:20]),
                "note": "Each case is rebuilt from its index k: "
                "fuzz.mutate(random.Random(f'a0:{k}'), fuzz.seeds()).",
            },
            indent=1,
        )
    )
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
