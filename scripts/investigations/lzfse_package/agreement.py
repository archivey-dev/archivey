"""Do the binding and the prototype agree on real LZFSE and LZVN data?

usage: python agreement.py [EXTRA.dmg ...]

Reads every file of the HFS+ and APFS fixtures with the prototype, recording each LZFSE
run and each LZVN or LZFSE decmpfs chunk the prototype decodes, then decodes each record
again with the binding (capped as `common.binding_capped`, raw LZVN wrapped as
`common.wrap_lzvn`). Extra DMGs (the corpus's LZFSE images) are checked run by run.
"""

from __future__ import annotations

import glob
import hashlib
import json
import os
import sys
import time

import common
import lzfse
from dmgproto import dmg, udif

records: list[tuple[str, bytes, int, bytes]] = []
_orig_decompress = common.proto.decompress
_orig_lzvn = common.proto.lzvn_decode


def _rec_decompress(src, max_out):
    out = _orig_decompress(src, max_out)
    records.append(("lzfse", bytes(src), max_out, out))
    return out


def _rec_lzvn(src, out, limit, stop_at=None):
    before = len(out)
    used = _orig_lzvn(src, out, limit, stop_at)
    if stop_at is None:
        records.append(("lzvn", bytes(src[:used]), limit - before, bytes(out[before:])))
    return used


def binding(kind, src, limit):
    if kind == "lzvn":
        return common.binding_capped(lzfse, common.wrap_lzvn(src, limit), limit)
    return common.binding_capped(lzfse, src, limit)


def check_fixtures():
    common.proto.decompress = _rec_decompress
    common.proto.lzvn_decode = _rec_lzvn
    per_image = {}
    for path in sorted(glob.glob(os.path.join(common.FIXTURES, "*.dmg"))):
        if "AES" in path:
            continue
        before = len(records)
        dmg.manifest(path)
        per_image[os.path.basename(path)] = len(records) - before
    common.proto.decompress = _orig_decompress
    common.proto.lzvn_decode = _orig_lzvn
    kinds: dict[str, list[int]] = {}
    for kind, src, limit, out in records:
        got = binding(kind, src, limit)
        k = kinds.setdefault(kind, [0, 0, 0])
        k[0] += 1
        k[1] += len(out)
        if got != out:
            k[2] += 1
    return {
        "records per image": {k: v for k, v in per_image.items() if v},
        "by kind (count, bytes, mismatches)": kinds,
    }


def check_image(path):
    img = udif.UdifImage(open(path, "rb"), os.path.getsize(path))  # noqa: SIM115  (the image keeps it)
    runs = [r for r in img.runs if r.kind == udif.LZFSE]
    n = mismatch = total = 0
    tp = tb = 0.0
    for r in runs:
        img.f.seek(r.offset)
        src = img.f.read(r.length)
        want = r.count * 512
        t = time.perf_counter()
        a = common.proto_decode(src, want)
        tp += time.perf_counter() - t
        t = time.perf_counter()
        b = common.binding_capped(lzfse, src, want)
        tb += time.perf_counter() - t
        n += 1
        total += len(a)
        mismatch += a != b or len(a) != want
    return {
        "LZFSE runs": n,
        "decoded MiB": round(total / 2**20, 1),
        "mismatches": mismatch,
        "prototype MB/s": round(total / tp / 1e6, 1) if tp else None,
        "binding MB/s (in process)": round(total / tb / 1e6, 1) if tb else None,
        "sha256 of the image": hashlib.sha256(open(path, "rb").read()).hexdigest()[:16],
    }


def main():
    res = {"fixtures": check_fixtures()}
    for p in sys.argv[1:]:
        res[os.path.basename(p)] = check_image(p)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
