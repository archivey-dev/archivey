"""API facts about the `lzfse` binding, each checked by running it.

usage: python probes.py   (with `lzfse` installed)

Each risky probe runs in a child process with an address-space limit, so a bomb or a
crash shows as an outcome instead of taking the run down.
"""

from __future__ import annotations

import ctypes
import json
import multiprocessing as mp
import os
import struct
import sys
import time

import common
import lzfse


def _child(fn, arg, limit, conn):
    common.set_memory_limit(limit)
    try:
        r = ("ok", fn(arg))
    except MemoryError:
        r = ("MemoryError", None)
    except Exception as e:  # noqa: BLE001
        r = (type(e).__module__ + "." + type(e).__name__, str(e))
    conn.send(
        r
    )  # a pipe, not a queue: a queue starts a thread, which the limit can refuse


def in_child(fn, arg, limit=None, timeout=60):
    # 1 GiB; a free-threaded build reserves more address space at start, so it needs more
    limit = limit or int(os.environ.get("PROBE_LIMIT_GIB", "1")) << 30
    parent, child = mp.Pipe(duplex=False)
    p = mp.Process(target=_child, args=(fn, arg, limit, child))
    p.start()
    got = parent.recv() if parent.poll(timeout) else None
    p.join(5)
    if p.is_alive():
        p.kill()
        return ("timeout", None)
    if got is None:
        return (f"died, exit code {p.exitcode}", None)
    return got


def decode_len(src):
    return len(lzfse.decompress(src))


def empty_stream():
    z = lzfse.compress(b"")
    try:
        return {"stream": z.hex(), "result": len(lzfse.decompress(z))}
    except Exception as e:  # noqa: BLE001
        return {"stream": z.hex(), "result": f"{type(e).__module__}.{type(e).__name__}"}


def short_inputs():
    out = {}
    for src in (b"", b"bvx$", b"bvx-\x00", b"bvx-\x05\x00\x00\x00ab"):
        r = in_child(decode_len, src)
        out[src.hex() or "(empty)"] = r[0]
    return out


def bomb(copies):
    """A stream of `copies` bvx2 blocks of 16 MiB of zeros each, under 1 KiB apiece."""
    one = lzfse.compress(bytes(16 << 20))
    assert one.endswith(common.ENDOFSTREAM)
    block = one[: -len(common.ENDOFSTREAM)]
    return block * copies + common.ENDOFSTREAM


def lzvn_wrap():
    """Encoder output for a small input is one bvxn block; unwrap and rewrap it."""
    data = (b"the quick brown fox " * 100)[:1900]
    z = lzfse.compress(data)
    magic = z[:4]
    if magic != common.LZVN:
        return {"encoder magic": magic.decode()}
    n_raw, n_payload = struct.unpack_from("<II", z, 4)
    payload = z[12 : 12 + n_payload]
    rewrapped = common.wrap_lzvn(payload, n_raw)
    return {
        "encoder magic": magic.decode(),
        "rewrapped decodes": lzfse.decompress(rewrapped) == data,
        "prototype raw lzvn": bytes(_proto_lzvn(payload, n_raw)) == data,
    }


def _proto_lzvn(payload, n_raw):
    out = bytearray()
    common.proto.lzvn_decode(payload, out, n_raw)
    return out


def ctypes_decode(lib, src, cap):
    """Apple's own entry point, called with our own buffer: one decode, capped."""
    buf = ctypes.create_string_buffer(cap + 1)
    n = lib.lzfse_decode_buffer(buf, cap + 1, src, len(src), None)
    if n == 0 or n > cap:
        raise ValueError("refused or over the cap")
    return buf.raw[:n]


def double_decode():
    """Time the binding against one direct decode of the same exact-size stream."""
    import random

    rnd = random.Random(1)
    words = [
        bytes(rnd.choice(b"abcdefghij ") for _ in range(rnd.randint(2, 9)))
        for _ in range(500)
    ]
    data = b"".join(rnd.choice(words) for _ in range(3000000))[: 16 << 20]
    z = lzfse.compress(data)
    lib = ctypes.CDLL(lzfse.__file__)
    lib.lzfse_decode_buffer.restype = ctypes.c_size_t
    lib.lzfse_decode_buffer.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
    ]
    assert ctypes_decode(lib, z, len(data)) == data == lzfse.decompress(z)

    def best(fn):
        ts = []
        for _ in range(5):
            t = time.perf_counter()
            fn()
            ts.append(time.perf_counter() - t)
        return min(ts)

    tb = best(lambda: lzfse.decompress(z))
    tc = best(lambda: ctypes_decode(lib, z, len(data)))
    return {
        "bytes": len(data),
        "binding ms": round(tb * 1000, 1),
        "one direct decode ms": round(tc * 1000, 1),
        "ratio": round(tb / tc, 2),
    }


def main():
    res = {"python": sys.version.split()[0]}
    gil = getattr(sys, "_is_gil_enabled", None)
    if gil is not None:
        res["GIL enabled after import"] = gil()
    res["empty stream"] = empty_stream()
    res["short inputs"] = short_inputs()
    res["raw LZVN"] = lzvn_wrap()
    for copies in (1, 16, 256):
        src = bomb(copies)
        res[f"bomb {copies} x 16 MiB in {len(src)} bytes, 1 GiB limit"] = {
            "binding": in_child(decode_len, src)[0],
            "walk declares": common.walk_blocks(src)[0],
        }
    res["exact-size stream"] = double_decode()
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
