"""Run shipped Python tests, cross-read their produced bytes, and replay C fuzz payloads.

Use metadata.py --download-sources first. Requires pytest and the packages in README.
Native C test binaries and sanitizers are not run by this script.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from c_api import bounded_raw, framed_decode
from common import ALGORITHMS, SNAPPY_PACKAGES, archivey_decode, decode, reference
from differential import observe


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sources", type=Path, required=True)
    p.add_argument("--output", type=Path, default=Path("work/snappy-upstream-results"))
    p.add_argument("--capture-worker", action="store_true")
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    cu_root = args.sources / "compress_utils-0.12.1"
    if not args.capture_worker:
        command = [
            sys.executable,
            __file__,
            "--sources",
            str(args.sources),
            "--output",
            str(args.output),
            "--capture-worker",
        ]
        with (args.output / "tests.log").open("w") as log:
            proc = subprocess.run(
                command, stdout=log, stderr=subprocess.STDOUT, timeout=180, check=False
            )
        print("upstream test process:", proc.returncode)
        return
    import compress_utils as cu
    import pytest

    captured = {}
    original = cu.compress
    inverse = {v: k for k, v in ALGORITHMS.items() if k != "lzma_alone"}

    def capture(data, algorithm, *pos, **kw):
        output = original(data, algorithm, *pos, **kw)
        name = algorithm if isinstance(algorithm, str) else algorithm.name
        kind = inverse.get(name)
        if kind and len(data) <= 1 << 20:
            captured[(kind, hashlib.sha256(output).hexdigest())] = (
                bytes(data),
                bytes(output),
            )
        return output

    cu.compress = capture
    paths = [
        cu_root / "bindings/python/tests",
        args.sources / "pysnappy-0.8.2/tests",
        args.sources / "python_snappy_pure-0.2.0/tests",
        args.sources / "python_snappy-0.7.3/test_snappy.py",
        args.sources / "python_snappy-0.7.3/test_formats.py",
    ]
    code = pytest.main(
        [
            "-q",
            "-rs",
            "--import-mode=importlib",
            f"--junitxml={args.output / 'tests.xml'}",
            *map(str, paths),
        ]
    )
    cu.compress = original
    rows = []
    for (kind, digest), (raw, data) in captured.items():
        observed = observe(
            lambda data=data, kind=kind, raw=raw: (
                reference("raw", data)
                if kind == "raw"
                else archivey_decode(kind, data, size=len(raw))
            )
        )
        expected = {
            "accepted": True,
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }
        rows.append(
            {
                "source": "compress-utils Python tests",
                "kind": kind,
                "input_sha256": digest,
                "size": len(raw),
                "expected": expected,
                "archivey_or_google": observed,
            }
        )
        if observed != expected:
            (args.output / f"{kind}-{digest}.bin").write_bytes(data)
    iris = (args.sources / "pysnappy-0.8.2/tests/iris.csv").read_bytes()
    import pysnappy

    iris_encoded = pysnappy.compress(iris)
    for package in SNAPPY_PACKAGES:
        observed = observe(lambda lib=package: decode(lib, "raw", iris_encoded))
        rows.append(
            {
                "source": "pysnappy iris.csv",
                "kind": "raw",
                "package": package,
                "result": observed,
                "expected_sha256": hashlib.sha256(iris).hexdigest(),
            }
        )
    regressions = []
    kinds = (
        "zstd",
        "brotli",
        "zlib",
        "bzip2",
        "lz4",
        "xz",
        "lzo",
        "gzip",
        "deflate",
        "raw",
        "lz4_raw",
    )
    for path in sorted((cu_root / "tests/fuzz/regressions").iterdir()):
        if path.name == "README.md":
            continue
        blob = path.read_bytes()
        kind = kinds[blob[0]]
        data = blob[2:]
        baseline = observe(
            lambda data=data, kind=kind: (
                reference("raw", data)
                if kind == "raw"
                else archivey_decode(
                    kind, data, size=4096 if kind in ("lzo", "lz4_raw") else None
                )
            )
        )
        candidate = observe(
            lambda data=data, kind=kind: (
                bounded_raw(kind, data, 128)
                if kind in ("lzo", "lz4_raw", "raw")
                else framed_decode(kind, data)
            )
        )
        regressions.append(
            {
                "name": path.name,
                "kind": kind,
                "mode_byte": blob[1],
                "reference": baseline,
                "candidate": candidate,
            }
        )
        # This replays the payload only. The upstream mode byte configures other C API
        # operations.
    fixture = cu_root / "tests/fixtures/lzo"
    raw = (fixture / "input.bin").read_bytes()
    timings = []
    for name in ("1.bin", "999.bin"):
        data = (fixture / name).read_bytes()
        for impl in ("archivey", "one-shot", "bounded"):
            call = (
                (lambda data=data, raw=raw: archivey_decode("lzo", data, size=len(raw)))
                if impl == "archivey"
                else (
                    lambda data=data, raw=raw: cu.decompress(
                        data, "lzo", expected_size=len(raw)
                    )
                )
                if impl == "one-shot"
                else (lambda data=data: bounded_raw("lzo", data))
            )
            samples = []
            for _ in range(7):
                start = time.perf_counter()
                out = call()
                samples.append(time.perf_counter() - start)
                if out != raw:
                    raise ValueError("LZO fixture bytes differ")
            timings.append(
                {
                    "fixture": name,
                    "implementation": impl,
                    "size": len(raw),
                    "samples": samples,
                }
            )
    result = {
        "pytest_exit": int(code),
        "cross_read_counts": dict(Counter(r["kind"] for r in rows)),
        "cross_reads": rows,
        "fuzz_payloads": regressions,
        "lzo_timing": timings,
    }
    (args.output / "upstream.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
