"""Compare every runnable package on identical bytes; save all differing observations.

uv run --with compress-utils==0.12.1 --with python-snappy==0.7.3 \
  --with py-snappy==0.1.0a1 --with python-snappy-pure==0.2.0 --with pysnappy==0.8.2 \
  python scripts/investigations/snappy_compress_utils/differential.py --output
  work/snappy-diff

Use a development checkout. Each package/codec runs in a watched child with a 1 GiB
address-space limit and 45 CPU seconds. Snappy has no archivey baseline: the reference
is system Google Snappy's validated raw decoder plus explicit framing/CRC checks.
Exit zero means the experiment completed, not that parity holds. Exceptions are data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import subprocess
import sys
from collections import Counter
from pathlib import Path

from c_api import bounded_raw, framed_decode
from common import (
    SNAPPY_PACKAGES,
    archivey_decode,
    decode,
    encode,
    mutations,
    payload,
    reference,
)


def observe(call):
    try:
        data = call()
        return {
            "accepted": True,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    except Exception as exc:  # noqa: BLE001 - observed result, not production translation
        return {"accepted": False, "error": type(exc).__name__, "message": str(exc)}


def candidate_decode(package, kind, mode, data, size):
    if mode == "bounded-framed":
        return framed_decode(kind, data)
    if mode == "bounded-raw":
        return bounded_raw(kind, data, total_limit=size)
    return decode(package, kind, data, streaming=mode == "stream", size=size)


def worker(package, kind, mode, data, target, size):
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    rows = []
    counts = Counter()
    for label, changed in mutations(data):
        if kind in ("raw", "framed", "hadoop"):
            ours = observe(lambda b=changed: reference(kind, b))
        else:
            ours = observe(lambda b=changed: archivey_decode(kind, b, size=size))
        theirs = observe(
            lambda b=changed: candidate_decode(package, kind, mode, b, size)
        )
        if ours["accepted"] and theirs["accepted"]:
            outcome = (
                "same_bytes"
                if ours["sha256"] == theirs["sha256"]
                else "different_bytes"
            )
        elif not ours["accepted"] and not theirs["accepted"]:
            outcome = "both_refuse"
        elif theirs["accepted"]:
            outcome = "candidate_only_accepts"
        else:
            outcome = "reference_only_accepts"
        counts[outcome] += 1
        if outcome not in ("same_bytes", "both_refuse"):
            name = f"{label}.bin"
            (target / name).write_bytes(changed)
            rows.append(
                {
                    "input": name,
                    "package": package,
                    "kind": kind,
                    "mode": mode,
                    "case": label,
                    "size_argument": size,
                    "outcome": outcome,
                    "reference": ours,
                    "candidate": theirs,
                }
            )
    (target / "summary.json").write_text(
        json.dumps(
            {
                "package": package,
                "kind": kind,
                "mode": mode,
                "counts": dict(counts),
                "valid_reference": observe(
                    lambda data=data, kind=kind: (
                        reference(kind, data)
                        if kind in ("raw", "framed", "hadoop")
                        else archivey_decode(kind, data, size=size)
                    )
                ),
                "valid_candidate": observe(
                    lambda data=data, kind=kind: candidate_decode(
                        package, kind, mode, data, size
                    )
                ),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (target / "differences.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/snappy-diff"))
    parser.add_argument(
        "--sources",
        type=Path,
        help="Extracted compress-utils source for its LZO fixtures",
    )
    parser.add_argument("--worker", nargs=5)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.worker:
        package, kind, mode, path, n = args.worker
        worker(
            package,
            kind,
            mode,
            Path(path).read_bytes(),
            args.output,
            int(n) if n != "none" else None,
        )
        return
    cases = [
        (p, "raw", "one-shot", encode("raw", payload(2048)), None)
        for p in SNAPPY_PACKAGES
    ]
    for mode in ("stream", "bounded-raw"):
        cases.append(
            ("compress-utils", "raw", mode, encode("raw", payload(2048)), None)
        )
    for p in ("python-snappy", "pysnappy", "cramjam"):
        cases.append((p, "framed", "one-shot", encode("framed", payload(2048)), None))
    for p in ("python-snappy", "pysnappy"):
        cases.append((p, "hadoop", "one-shot", encode("hadoop", payload(4096)), None))
    for k in (
        "gzip",
        "zlib",
        "deflate",
        "bzip2",
        "xz",
        "lzma_alone",
        "zstd",
        "lz4",
        "brotli",
        "lz4_raw",
    ):
        data = encode(k, payload(2048))
        cases.append(
            ("compress-utils", k, "one-shot", data, 2048 if k == "lz4_raw" else None)
        )
        cases.append(
            ("compress-utils", k, "stream", data, 2048 if k == "lz4_raw" else None)
        )
        if k not in ("lzma_alone", "lz4_raw"):
            cases.append(("compress-utils", k, "bounded-framed", data, None))
        if k == "lz4_raw":
            cases.append(("compress-utils", k, "bounded-raw", data, 2048))
    if args.sources:
        for f in ("1.bin", "999.bin"):
            folder = args.sources / "tests/fixtures/lzo"
            for mode in ("one-shot", "stream", "bounded-raw"):
                cases.append(
                    (
                        "compress-utils",
                        "lzo",
                        mode,
                        (folder / f).read_bytes(),
                        len((folder / "input.bin").read_bytes()),
                    )
                )
    summaries = []
    differences = []
    for i, (package, kind, mode, data, n) in enumerate(cases):
        folder = args.output / f"{i:02d}-{package}-{kind}-{mode}"
        folder.mkdir(exist_ok=True)
        path = folder / "valid.bin"
        path.write_bytes(data)
        command = [
            sys.executable,
            __file__,
            "--output",
            str(folder),
            "--worker",
            package,
            kind,
            mode,
            str(path),
            str(n) if n is not None else "none",
        ]
        try:
            p = subprocess.run(command, capture_output=True, timeout=60, check=False)
            if p.returncode:
                summary = {
                    "package": package,
                    "kind": kind,
                    "mode": mode,
                    "worker_exit": p.returncode,
                    "stderr": p.stderr.decode(errors="replace"),
                }
            else:
                summary = json.loads(
                    (folder / "summary.json").read_text(encoding="utf-8")
                )
                for row in json.loads(
                    (folder / "differences.json").read_text(encoding="utf-8")
                ):
                    row["input"] = f"{folder.name}/{row['input']}"
                    differences.append(row)
        except subprocess.TimeoutExpired:
            summary = {"package": package, "kind": kind, "mode": mode, "timeout": True}
        summaries.append(summary)
        print(package, kind, mode, summary.get("counts", summary), flush=True)
    for name, rows in [("summary", summaries), ("differences", differences)]:
        (args.output / f"{name}.json").write_text(
            json.dumps(rows, indent=2), encoding="utf-8"
        )


if __name__ == "__main__":
    main()
