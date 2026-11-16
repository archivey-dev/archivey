"""Matched valid-input throughput, import latency, and fresh-process output/RSS probes.

Use the README's pinned run_candidates invocation. Timings validate complete bytes.
The pure Python implementations receive the same 4 KiB/1 MiB Snappy payloads. Raw and
common-codec timings and memory probes use resource-limited, watched workers.
Framed/Hadoop throughput runs in the parent process on valid, self-encoded input only.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import io
import json
import resource
import statistics
import subprocess
import sys
import time
from pathlib import Path

from c_api import BoundedDecoder, bounded_raw, framed_decode
from common import (
    SNAPPY_PACKAGES,
    archivey_decode,
    decode,
    encode,
    payload,
    rss_kib,
)


def measure(call, expected, repeats=5):
    samples = []
    try:
        start = time.perf_counter()
        got = call()
        elapsed = time.perf_counter() - start
        if got != expected:
            return {"error": "different bytes", "size": len(got)}
        iterations = max(1, min(2000, int(0.03 / max(elapsed, 1e-9))))
        for _ in range(repeats):
            start = time.perf_counter()
            for _ in range(iterations):
                got = call()
            elapsed = (time.perf_counter() - start) / iterations
            if got != expected:
                return {"error": "different bytes", "size": len(got)}
            samples.append(elapsed)
    except Exception as e:  # noqa: BLE001 - observed outcome
        return {"error": type(e).__name__, "message": str(e)}
    median = statistics.median(samples)
    return {
        "seconds": median,
        "MB_s": len(expected) / median / 1e6,
        "samples": samples,
        "batch_iterations": iterations,
    }


def timing_worker(package, kind, mode, path, n):
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    data = path.read_bytes()
    expected = payload(n)
    baseline = (
        (lambda data=data: decode("pysnappy", "raw", data))
        if kind == "raw"
        else (
            lambda data=data, kind=kind: archivey_decode(
                kind, data, streaming=mode != "one-shot", size=n
            )
        )
    )
    call = (
        (lambda data=data, kind=kind: framed_decode(kind, data, streaming=True))
        if mode == "bounded-framed"
        else (lambda data=data, kind=kind: bounded_raw(kind, data))
        if mode == "bounded-raw"
        else (
            lambda data=data, kind=kind: decode(
                package,
                kind,
                data,
                streaming=mode == "stream",
                size=n if kind in ("lz4_raw", "lzo") else None,
            )
        )
    )
    a = measure(baseline, expected, 3 if package == "py-snappy" else 5)
    b = measure(call, expected, 3 if package == "py-snappy" else 5)
    result = {
        "package": package,
        "kind": kind,
        "mode": mode,
        "size": n,
        "compressed_size": len(data),
        "reference": a,
        "candidate": b,
    }
    if "seconds" in a and "seconds" in b:
        result["speed_ratio"] = a["seconds"] / b["seconds"]
    print(json.dumps(result))


def memory_worker(package, kind, path):
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    modules = {
        "python-snappy": "snappy",
        "python-snappy-pure": "python_snappy",
        "py-snappy": "py_snappy",
        "pysnappy": "pysnappy",
        "compress-utils": "compress_utils",
        "bounded": "compress_utils",
        "baseline": "archivey",
    }
    importlib.import_module(modules[package])
    data = path.read_bytes()
    before = rss_kib()
    result = {"package": package, "kind": kind, "before_kib": before}
    try:
        if package == "bounded":
            d = BoundedDecoder(kind, single=kind not in ("lzo", "lz4_raw", "raw"))
            try:
                block = d.decompress(data, 128)
                result.update(
                    first_bytes=len(block), needs_input=d.needs_input, eof=d.eof
                )
                if kind == "raw" and not block:
                    d.end_input()
                    block = d.decompress(b"", 128)
                    result["finish_bytes"] = len(block)
            finally:
                d.close()
        elif package == "compress-utils":
            import compress_utils as cu

            alg = {"bzip2": "bz2", "raw": "snappy"}.get(kind, kind)
            d = cu.DecompressStream(alg, max_output=128)
            block = d.decompress(data)
            result["first_bytes"] = len(block)
            if kind == "raw":
                result["finish_bytes"] = len(d.finish())
        elif package == "baseline" and kind in ("lzo", "lz4_raw"):
            result["first_bytes"] = len(archivey_decode(kind, data, size=16 << 20))
        elif package == "baseline" and kind != "raw":
            from common import CONFIG, Codec, open_codec_stream

            with open_codec_stream(
                Codec(kind), io.BytesIO(data), config=CONFIG
            ) as stream:
                result["first_bytes"] = len(stream.read(128))
        else:
            result["first_bytes"] = len(decode(package, kind, data))
    except Exception as exc:  # noqa: BLE001 - measured failure
        result.update(error=type(exc).__name__, message=str(exc))
    result["peak_kib"] = rss_kib()
    print(json.dumps(result))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=Path("work/snappy-bench"))
    p.add_argument("--worker", nargs=5)
    p.add_argument("--memory-worker", nargs=3)
    p.add_argument("--sources", type=Path)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.worker:
        package, kind, mode, path, n = args.worker
        timing_worker(package, kind, mode, Path(path), int(n))
        return
    if args.memory_worker:
        package, kind, path = args.memory_worker
        memory_worker(package, kind, Path(path))
        return
    rows = []
    cases = []
    for size in (4096, 1 << 20):
        for package in SNAPPY_PACKAGES:
            cases.append((package, "raw", "one-shot", size))
        for mode in ("stream", "bounded-raw"):
            cases.append(("compress-utils", "raw", mode, size))
        for kind in (
            "gzip",
            "zlib",
            "deflate",
            "bzip2",
            "xz",
            "zstd",
            "lz4",
            "brotli",
            "lz4_raw",
            "lzo",
        ):
            for mode in (
                "one-shot",
                "stream",
                "bounded-raw" if kind in ("lz4_raw", "lzo") else "bounded-framed",
            ):
                cases.append(("compress-utils", kind, mode, size))
    for package, kind, mode, size in cases:
        data = encode(kind, payload(size))
        path = args.output / f"input-{kind}-{size}.bin"
        path.write_bytes(data)
        try:
            r = subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "--worker",
                    package,
                    kind,
                    mode,
                    str(path),
                    str(size),
                ],
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            row = (
                json.loads(r.stdout)
                if not r.returncode
                else {
                    "package": package,
                    "kind": kind,
                    "mode": mode,
                    "size": size,
                    "worker_exit": r.returncode,
                    "stderr": r.stderr,
                }
            )
        except subprocess.TimeoutExpired:
            row = {
                "package": package,
                "kind": kind,
                "mode": mode,
                "size": size,
                "timeout": True,
            }
        rows.append(row)
        print(
            package,
            kind,
            mode,
            size,
            row.get("speed_ratio", row.get("candidate", row)),
            flush=True,
        )
    # Compare framed/Hadoop streaming throughput on both API families, using a fast raw
    # oracle.
    for size in (4096, 1 << 20):
        for kind, packages in [
            ("framed", ("python-snappy", "pysnappy", "cramjam")),
            ("hadoop", ("python-snappy", "pysnappy")),
        ]:
            data = encode(kind, payload(size))
            for package in packages:
                for streaming in (False, True):
                    result = measure(
                        lambda lib=package, k=kind, b=data, s=streaming: decode(
                            lib, k, b, s
                        ),
                        payload(size),
                    )
                    rows.append(
                        {
                            "package": package,
                            "kind": kind,
                            "mode": "stream" if streaming else "one-shot",
                            "size": size,
                            "candidate": result,
                        }
                    )
    memory = []
    for kind in (
        "raw",
        "gzip",
        "zlib",
        "deflate",
        "bzip2",
        "xz",
        "zstd",
        "lz4",
        "brotli",
        "lz4_raw",
        "lzo",
    ):
        path = args.output / f"bomb-{kind}.bin"
        path.write_bytes(encode(kind, b"\0" * (16 << 20)))
        packages = (
            SNAPPY_PACKAGES + ("bounded",)
            if kind == "raw"
            else ("baseline", "compress-utils", "bounded")
        )
        for package in packages:
            if package == "cramjam":
                continue
            try:
                proc = subprocess.run(
                    [
                        sys.executable,
                        __file__,
                        "--memory-worker",
                        package,
                        kind,
                        str(path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
                memory.append(
                    json.loads(proc.stdout)
                    if proc.returncode == 0
                    else {
                        "package": package,
                        "kind": kind,
                        "exit": proc.returncode,
                        "stderr": proc.stderr,
                    }
                )
            except subprocess.TimeoutExpired:
                memory.append({"package": package, "kind": kind, "timeout": True})
    imports = {}
    for module in (
        "compress_utils",
        "py_snappy",
        "python_snappy",
        "snappy",
        "pysnappy",
    ):
        code = f"import time; t=time.perf_counter(); import {module}; print(time.perf_counter()-t)"
        imports[module] = [
            float(subprocess.check_output([sys.executable, "-c", code], text=True))
            for _ in range(7)
        ]
    for name, data in [("throughput", rows), ("memory", memory), ("imports", imports)]:
        (args.output / f"{name}.json").write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )


if __name__ == "__main__":
    main()
