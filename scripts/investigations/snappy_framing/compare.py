"""Compare the two raw Snappy backends under archivey's framing.

usage: python compare.py {correctness,mutations,speed,memory,stability,all} OUTDIR

Writes OUTDIR/<part>.json. Run ``speed`` on an otherwise idle host.
"""

# Each lambda here is called at once, inside its loop iteration.
# ruff: noqa: B023

from __future__ import annotations

import hashlib
import json
import random
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import common as C

SIZES = (1024, 300_000, 4 << 20)


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def correctness() -> dict:
    rows = []
    for size in SIZES:
        for kind, data in C.payloads(size).items():
            for producer, produce in C.producers().items():
                sz = produce(data)
                row = {"size": size, "payload": kind, "producer": producer}
                ref = C.outcome(lambda: C.reference_framed(sz))
                row["reference"] = ref[0] == "ok" and ref[1] == data
                for b in C.BACKEND_NAMES:
                    got = C.outcome(lambda b=b: C.archivey_read(b, sz))
                    row[b] = got[0] == "ok" and got[1] == data
                rows.append(row)
    bad = [r for r in rows if not all(r[k] for k in ("reference", *C.BACKEND_NAMES))]
    return {"cases": len(rows), "failures": bad}


def _mutations(data: bytes, rng: random.Random):
    yield "valid", data
    for i in sorted(
        {rng.randrange(len(data)) for _ in range(64)} | {0, 5, 10, 13, len(data) - 1}
    ):
        yield f"cut-{i}", data[:i]
    for i in range(256):
        b = bytearray(data)
        pos = rng.randrange(len(b))
        b[pos] ^= 1 << rng.randrange(8)
        yield f"flip-{pos}", bytes(b)
    for i in range(64):
        b = bytearray(data)
        pos = rng.randrange(len(b))
        b[pos] = rng.randrange(256)
        yield f"byte-{pos}", bytes(b)
    yield "trailing", data + b"TRAILING"
    yield "zeros", data + bytes(4)
    yield "concat", data + data


def mutations() -> dict:
    rng = random.Random(11)
    summary: dict[str, int] = {}
    disagreements = []
    total = 0
    for producer, produce in C.producers().items():
        for kind, data in C.payloads(200_000).items():
            sz = produce(data)
            for name, m in _mutations(sz, rng):
                total += 1
                ref = C.outcome(lambda: C.reference_framed(m))
                res = {
                    b: C.outcome(lambda b=b: C.decode_with(b, m))
                    for b in C.BACKEND_NAMES
                }
                res_drip = {
                    b: C.outcome(
                        lambda b=b: C.decode_with(b, m, step=4099, max_length=777)
                    )
                    for b in C.BACKEND_NAMES
                }
                key = ref[0]
                summary[key] = summary.get(key, 0) + 1
                norm = lambda r: (r[0], _h(r[1]) if r[0] == "ok" else None)  # noqa: E731
                outs = (
                    {"reference": norm(ref)}
                    | {b: norm(r) for b, r in res.items()}
                    | {f"{b}/drip": norm(r) for b, r in res_drip.items()}
                )
                if len(set(outs.values())) != 1:
                    disagreements.append(
                        {
                            "producer": producer,
                            "payload": kind,
                            "mutation": name,
                            "outcomes": outs,
                        }
                    )
    return {
        "inputs": total,
        "reference_outcomes": summary,
        "disagreements": disagreements,
    }


def _rate(fn, nbytes: int, repeat: int = 5) -> float:
    times = []
    for _ in range(repeat):
        t = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t)
    return nbytes / statistics.median(times) / 1e6


def speed() -> dict:
    import cramjam

    out: dict = {"kernel_64k_MBps": {}, "framed_16MiB_MBps": {}}
    for kind, data in C.payloads(16 << 20).items():
        chunks = C.split(data)
        blocks = [C.google_compress_raw(c) for c in chunks]
        for b, dec in C.DECODERS.items():
            out["kernel_64k_MBps"][f"{kind}/{b}"] = round(
                _rate(
                    lambda dec=dec: [C.decode_raw_chunk(dec, x) for x in blocks],
                    len(data),
                ),
                1,
            )
        out["kernel_64k_MBps"][f"{kind}/google-ctypes"] = round(
            _rate(lambda: [C.google_raw(x) for x in blocks], len(data)), 1
        )
        sz = C.producers()["cramjam-framed"](data)
        for b in C.BACKEND_NAMES:
            for crc in ("google-crc32c", "python"):
                out["framed_16MiB_MBps"][f"{kind}/{b}/crc={crc}"] = round(
                    _rate(
                        lambda b=b, crc=crc: C.archivey_read(b, sz, crc), len(data), 3
                    ),
                    1,
                )
        out["framed_16MiB_MBps"][f"{kind}/cramjam-own-framing"] = round(
            _rate(lambda: bytes(cramjam.snappy.decompress(sz)), len(data)), 1
        )
    return out


_CHILD = r"""
import io, sys
sys.path.insert(0, sys.argv[1])
import common as C
from archivey import open_stream
config = C.snappy_config(sys.argv[2], "google-crc32c")
data = bytes(64 << 20)
sz = C.producers()["cramjam-framed"](data)
del data
def hwm():
    for line in open("/proc/self/status"):
        if line.startswith("VmHWM"):
            return int(line.split()[1])
base = hwm()
n = 0
with open_stream(io.BytesIO(sz), format="sz", config=config) as s:
    while chunk := s.read(1 << 20):
        n += len(chunk)
print(n, hwm() - base)
"""


def memory() -> dict:
    out = {}
    for b in C.BACKEND_NAMES:
        r = subprocess.run(
            [sys.executable, "-c", _CHILD, str(Path(__file__).parent), b],
            capture_output=True,
            text=True,
            check=True,
        )
        n, kib = r.stdout.split()
        out[b] = {"decoded": int(n), "extra_peak_rss_KiB": int(kib)}
    return out


def _rss_kib() -> int:
    with open("/proc/self/status") as status:
        for line in status:
            if line.startswith("VmRSS"):
                return int(line.split()[1])
    return 0


def stability() -> dict:
    """Leak check on refused input, and concurrent decodes from four threads."""
    data = C.payloads(300_000)["text"]
    sz = C.producers()["cramjam-framed"](data)
    bad = bytearray(sz)
    bad[100] ^= 0x10
    raw_bad = [
        bytes([5, 0xF4, 0, 0, 0]),
        b"\x04\x01\x00",
        b"\xff\xff\x03" + b"\x00" * 50,
    ]
    out: dict = {}
    for b, dec in C.DECODERS.items():
        for _ in range(2000):
            C.outcome(lambda: C.decode_raw_chunk(dec, raw_bad[0]))
        before = _rss_kib()
        for i in range(200_000):
            C.outcome(lambda: C.decode_raw_chunk(dec, raw_bad[i % 3]))
        for _ in range(200):
            C.outcome(lambda: C.decode_with(b, bytes(bad)))
        out[f"{b}/rss_growth_KiB"] = _rss_kib() - before
        errors: list[str] = []

        def work(b=b, errors=errors) -> None:
            for _ in range(30):
                if C.decode_with(b, sz) != data:
                    errors.append("mismatch")

        threads = [threading.Thread(target=work) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        out[f"{b}/threaded_mismatches"] = len(errors)
    return out


PARTS = {
    "correctness": correctness,
    "mutations": mutations,
    "speed": speed,
    "memory": memory,
    "stability": stability,
}

if __name__ == "__main__":
    which, outdir = sys.argv[1], Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    for name in PARTS if which == "all" else [which]:
        t = time.time()
        result = PARTS[name]()
        (outdir / f"{name}.json").write_text(json.dumps(result, indent=1) + "\n")
        print(name, f"{time.time() - t:.0f}s", json.dumps(result)[:400], flush=True)
