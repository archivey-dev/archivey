"""Classify the fuzz run's repro cases (results/fuzz-work/*.jsonl) by cause.

usage: python classify.py
"""

from __future__ import annotations

import glob
import json
import os
from collections import Counter
from pathlib import Path

import common
import fuzz
import lzfse

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    seeds = {data for data, _ in fuzz.seeds()}
    dis, mem, over, proto_other, left = Counter(), Counter(), 0, Counter(), Counter()
    total_matches = Counter()
    examples = {}
    for f in glob.glob(os.path.join(HERE, "results", "fuzz-work", "*.jsonl")):
        for line in Path(f).read_text().splitlines():
            r = json.loads(line)
            if "src" not in r:
                continue
            src, limit = bytes.fromhex(r["src"]), r["limit"]
            if not r["agree"]:
                try:
                    common.proto_decode(src, limit)
                    why = "prototype accepts"
                except Exception as e:  # noqa: BLE001
                    why = f"{type(e).__name__}: {e}"
                    why = why.split(" at ")[0]
                    for n in "0123456789":
                        why = why.replace(n, "#")
                side = (
                    "binding accepts" if r["capped"] == "bytes" else "binding refuses"
                )
                out = lzfse.decompress(src) if r["capped"] == "bytes" else None
                same = None if out is None else out in seeds
                declared = common.walk_blocks(src)[0]
                key = (
                    why,
                    side,
                    "output is a seed's data"
                    if same
                    else "other output"
                    if out is not None
                    else "-",
                )
                dis[key] += 1
                if out is not None:
                    total_matches[len(out) == declared] += 1
                examples.setdefault(key, (r["k"], r["src"][:120], limit))
                try:
                    got = common.binding_checked(lzfse, src, limit)
                    got = got if len(got) == limit else None
                except (common.BadStream, lzfse.error, MemoryError):
                    got = None
                try:
                    want = common.proto_decode(src, limit)
                    want = want if len(want) == limit else None
                except Exception:  # noqa: BLE001
                    want = None
                if got != want:
                    left[key] += 1
            if r["capped"] == "MemoryError":
                mem[len(src) // 100 * 100] += 1
            if r["capped"] == "AssertionError":
                over += 1
            if r["proto"] not in ("bytes", "LzfseError"):
                try:
                    common.proto_decode(src, limit)
                except Exception as e:  # noqa: BLE001
                    proto_other[f"{type(e).__module__}.{type(e).__name__}: {e}"] += 1
    print("disagreements by cause:")
    for k, v in dis.most_common():
        print(f"  {v:6}  {k}")
    print(
        "binding-accepted disagreements whose output length equals the walk's declared total:",
        dict(total_matches),
    )
    print(
        "capped call raised MemoryError under the 1 GiB limit, by input size"
        " (bytes, rounded down to 100):",
        dict(sorted(mem.items())),
    )
    print("capped call returned more than the limit:", over)
    print("prototype errors other than LzfseError:")
    for k, v in proto_other.most_common(8):
        print(f"  {v:6}  {k}")
    print(
        "disagreements left with common.binding_checked (strict walk + length check):"
    )
    for k, v in left.most_common():
        print(f"  {v:6}  {k}")
    print("examples:")
    for k, v in examples.items():
        print(" ", k, v)


if __name__ == "__main__":
    main()
