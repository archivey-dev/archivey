"""Throughput, import latency, incremental-input probes and bounded-output/RSS probes.

uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
    scripts/investigations/codec_libraries/bench.py --output work/codec-bench

Times include Python output copies, parsing and verification. Both libraries get
identical sizes, payloads, repeats and baseline calls. A refused streaming call is
recorded rather than replaced with a one-shot result. RSS is Linux KiB, measured in
fresh processes with compressed input on disk, and includes interpreter/imports.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import os
import platform
import resource
import statistics
import subprocess
import sys
import time
from pathlib import Path

from common import (
    CONFIG,
    CONTAINERS,
    CRAMJAM,
    STREAM_CONFIG,
    UNPACKIO,
    Codec,
    archivey,
    baseline,
    candidate,
    encode,
    fixture_cases,
    io,
    open_codec_stream,
    payload,
)


def peak_rss():
    # getrusage may inherit a pre-exec high-water mark from the benchmark parent.
    # Linux VmHWM is the high-water mark of this executable's current mm_struct.
    for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1])
    raise RuntimeError("Linux /proc/self/status VmHWM is required")


def timed(call, expected: bytes, repeats: int):
    times = []
    try:
        for _ in range(repeats):
            start = time.perf_counter()
            output = call()
            elapsed = time.perf_counter() - start
            if output != expected:
                return {"error": "different bytes", "output_size": len(output)}
            times.append(elapsed)
    except Exception as exc:  # noqa: BLE001 - record the observed API failure
        return {"error": type(exc).__name__, "message": str(exc)}
    seconds = statistics.median(times)
    return {
        "median_seconds": seconds,
        "MB_per_second": len(expected) / seconds / 1e6,
        "samples_seconds": times,
    }


def memory_worker(library: str, kind: str, source: Path, limit: int):
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    data = source.read_bytes()
    importlib.import_module(
        library.split("_")[0] if library != "baseline" else "archivey"
    )
    before = peak_rss()
    result = {"library": library, "kind": kind, "before_rss_kib": before}
    try:
        if kind.startswith(("zip_", "7z")):
            fmt = "zip" if kind.startswith("zip_") else "7z"
            if library == "baseline":
                with (
                    archivey.open_archive(
                        io.BytesIO(data), format=fmt, config=CONFIG
                    ) as archive,
                    archive.open(archive.members()[0]) as stream,
                ):
                    result["first_output_bytes"] = len(stream.read(128))
                    result["first_rss_kib"] = peak_rss()
            else:
                import unpackio

                limits = (
                    unpackio.Limits()
                    if limit < 0
                    else unpackio.Limits(
                        max_entry_output_bytes=limit, max_total_output_bytes=limit
                    )
                )
                opener = unpackio.open_bytes if fmt == "7z" else unpackio.open_zip_bytes
                archive = opener(data, limits=limits)

                def first_chunk(chunk):
                    result["first_output_bytes"] = len(chunk)
                    result["first_rss_kib"] = peak_rss()
                    return False

                archive.stream_entry(0, first_chunk)
        elif library == "baseline":
            with open_codec_stream(
                Codec(kind), io.BytesIO(data), config=STREAM_CONFIG
            ) as stream:
                result["first_output_bytes"] = len(stream.read(limit))
                result["first_rss_kib"] = peak_rss()
                total = result["first_output_bytes"]
                while block := stream.read(65536):
                    total += len(block)
                result["total_output_bytes"] = total
        elif library == "cramjam_into":
            import cramjam

            module = getattr(cramjam, "xz" if kind == "lzma_alone" else kind)
            output = bytearray(limit)
            result["into_return"] = module.decompress_into(data, output)
        elif library == "cramjam":
            import cramjam

            module = getattr(cramjam, "xz" if kind == "lzma_alone" else kind)
            output = module.decompress(data, output_len=limit)
            result["first_output_bytes"] = len(output)
            result["first_rss_kib"] = peak_rss()
            del output
            into = bytearray(limit)
            try:
                result["into_return"] = module.decompress_into(data, into)
            except Exception as exc:  # noqa: BLE001 - observed result
                result["into_error"] = type(exc).__name__ + ": " + str(exc)
        else:
            import unpackio

            limits = (
                unpackio.Limits()
                if limit < 0
                else unpackio.Limits(
                    max_entry_output_bytes=limit, max_total_output_bytes=limit
                )
            )
            stream = unpackio.open_stream_bytes(
                data, format=kind.replace("unix_compress", "z"), limits=limits
            )

            def receive(chunk):
                result["first_output_bytes"] = len(chunk)
                result["first_rss_kib"] = peak_rss()
                return False

            stream.stream(receive)
    except Exception as exc:  # noqa: BLE001 - observed result
        result["error"] = type(exc).__name__ + ": " + str(exc)
    result["peak_rss_kib"] = peak_rss()
    print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/codec-bench"))
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--memory-worker", nargs=4)
    parser.add_argument("--memory-only", action="store_true")
    args = parser.parse_args()
    if args.memory_worker:
        library, kind, source, limit = args.memory_worker
        memory_worker(library, kind, Path(source), int(limit))
        return
    args.output.mkdir(parents=True, exist_ok=True)
    environment = {
        "python": sys.version,
        "platform": platform.platform(),
        "cpus_visible": os.cpu_count(),
        "payload_seed": 81073,
        "versions": {
            name: importlib.metadata.version(name)
            for name in (
                "cramjam",
                "unpackio",
                "brotli",
                "lz4",
                "backports.zstd",
                "pyppmd",
                "inflate64",
                "py7zr",
                "ncompress",
            )
        },
    }
    (args.output / "environment.json").write_text(
        json.dumps(environment, indent=2), encoding="utf-8"
    )
    rows = []
    for size in () if args.memory_only else (4096, 8 << 20):
        raw = payload(size)
        for library, kinds in (
            ("cramjam", CRAMJAM),
            ("unpackio", UNPACKIO + CONTAINERS),
        ):
            for kind in kinds:
                data = encode(kind, raw)
                for streaming in (False, True):
                    ours = timed(
                        lambda k=kind, d=data, s=streaming: baseline(k, d, s),
                        raw,
                        args.repeats,
                    )
                    theirs = timed(
                        lambda k=kind, d=data, s=streaming, lib=library: candidate(
                            lib, k, d, s
                        ),
                        raw,
                        args.repeats,
                    )
                    row = {
                        "library": library,
                        "kind": kind,
                        "size": size,
                        "compressed_size": len(data),
                        "streaming": streaming,
                        "archivey": ours,
                        "candidate": theirs,
                    }
                    if "median_seconds" in ours and "median_seconds" in theirs:
                        row["speed_ratio"] = (
                            ours["median_seconds"] / theirs["median_seconds"]
                        )
                    rows.append(row)
                    print(
                        library,
                        kind,
                        size,
                        streaming,
                        row.get("speed_ratio", theirs),
                        flush=True,
                    )
    fixtures = {} if args.memory_only else fixture_cases()
    for label, (kind, data) in fixtures.items():
        try:
            expected = baseline(kind, data, include_hardlinks=False)
        except Exception as exc:  # noqa: BLE001 - unsupported oracle fixture
            rows.append(
                {
                    "library": "unpackio",
                    "kind": kind,
                    "fixture": label,
                    "baseline_error": type(exc).__name__ + ": " + str(exc),
                }
            )
            continue
        for streaming in (False, True):
            ours = timed(
                lambda k=kind, d=data, mode=streaming: baseline(
                    k, d, mode, include_hardlinks=False
                ),
                expected,
                args.repeats,
            )
            theirs = timed(
                lambda k=kind, d=data, mode=streaming: candidate(
                    "unpackio", k, d, mode
                ),
                expected,
                args.repeats,
            )
            row = {
                "library": "unpackio",
                "kind": kind,
                "fixture": label,
                "payload_scope": "regular members only; hardlinks compared in differential",
                "size": len(expected),
                "streaming": streaming,
                "archivey": ours,
                "candidate": theirs,
            }
            if "median_seconds" in ours and "median_seconds" in theirs:
                row["speed_ratio"] = ours["median_seconds"] / theirs["median_seconds"]
            rows.append(row)
    imports = {}
    for module in () if args.memory_only else ("archivey", "cramjam", "unpackio"):
        code = (
            "import time,importlib; t=time.perf_counter(); "
            f"importlib.import_module('{module}'); print(time.perf_counter()-t)"
        )
        imports[module] = [
            float(subprocess.check_output([sys.executable, "-c", code], text=True))
            for _ in range(9)
        ]
    memory = []
    for kind in (
        "gzip",
        "zlib",
        "deflate",
        "bzip2",
        "xz",
        "lzma_alone",
        "zstd",
        "lz4",
        "brotli",
        "unix_compress",
        "zip_deflate",
        "7z",
    ):
        path = args.output / f"bomb-{kind}.bin"
        path.write_bytes(encode(kind, b"\0" * (16 << 20)))
        libraries = ["baseline"]
        if kind in CRAMJAM:
            libraries.extend(("cramjam", "cramjam_into"))
        if kind in UNPACKIO or kind.startswith(("zip_", "7z")):
            libraries.append("unpackio")
        for library in libraries:
            command = [
                sys.executable,
                __file__,
                "--memory-worker",
                library,
                kind,
                str(path),
                "128",
            ]
            try:
                result = subprocess.run(
                    command, capture_output=True, text=True, timeout=60, check=False
                )
                memory.append(
                    json.loads(result.stdout)
                    if result.returncode == 0
                    else {
                        "library": library,
                        "kind": kind,
                        "worker_exit": result.returncode,
                        "stderr": result.stderr,
                    }
                )
            except subprocess.TimeoutExpired:
                memory.append({"library": library, "kind": kind, "timeout": True})
    # Also observe the first callback without a small configured total-output cap.
    for kind in (*UNPACKIO, "zip_deflate", "7z"):
        command = [
            sys.executable,
            __file__,
            "--memory-worker",
            "unpackio",
            kind,
            str(args.output / f"bomb-{kind}.bin"),
            "-1",
        ]
        process = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False
        )
        result = (
            json.loads(process.stdout)
            if process.returncode == 0
            else {
                "kind": kind,
                "worker_exit": process.returncode,
                "stderr": process.stderr,
            }
        )
        result["default_limits_first_callback"] = True
        memory.append(result)
    outputs = [("memory", memory)]
    if not args.memory_only:
        outputs.extend((("throughput", rows), ("imports", imports)))
    for name, value in outputs:
        (args.output / f"{name}.json").write_text(
            json.dumps(value, indent=2), encoding="utf-8"
        )


if __name__ == "__main__":
    main()
