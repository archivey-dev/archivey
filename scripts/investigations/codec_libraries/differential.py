"""Compare acceptance and output; save EVERY difference with its input and outcomes.

uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
    scripts/investigations/codec_libraries/differential.py --output work/codec-diff

Run from an archivey checkout with development dependencies installed. Each family
runs in a watched child with Linux resource bounds. Exceptions are observations,
not translated into an assumed corruption/truncation taxonomy. Exit 0 means the
experiment completed, NOT that parity holds. See summary.json and differences.json.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import resource
import subprocess
import sys
from collections import Counter
from pathlib import Path

from common import (
    CONTAINERS,
    CRAMJAM,
    UNPACKIO,
    baseline,
    candidate,
    encode,
    fixture_cases,
    mutations,
    payload,
)


def observe(call):
    try:
        output = call()
        return {
            "accepted": True,
            "size": len(output),
            "sha256": hashlib.sha256(output).hexdigest(),
        }
    except Exception as exc:  # noqa: BLE001 - the exception is experimental data
        return {"accepted": False, "error": type(exc).__name__, "message": str(exc)}


def worker(library: str, label: str, kind: str, data: bytes, target: Path):
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    results = Counter()
    differences = []
    target.mkdir(parents=True, exist_ok=True)
    for mutation, changed in mutations(data):
        ours = observe(lambda b=changed: baseline(kind, b))
        theirs = observe(lambda b=changed: candidate(library, kind, b))
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
            outcome = "archivey_only_accepts"
        results[outcome] += 1
        if outcome in (
            "different_bytes",
            "candidate_only_accepts",
            "archivey_only_accepts",
        ):
            name = f"{library}-{label}-{mutation}.bin"
            (target / name).write_bytes(changed)
            differences.append(
                {
                    "input": name,
                    "mutation": mutation,
                    "kind": kind,
                    "outcome": outcome,
                    "archivey": ours,
                    library: theirs,
                }
            )
    summary = {
        "library": library,
        "label": label,
        "kind": kind,
        "counts": dict(results),
        "valid": {
            "archivey": observe(lambda: baseline(kind, data)),
            library: observe(lambda: candidate(library, kind, data)),
        },
        "peak_rss_kib": int(
            next(
                line.split()[1]
                for line in Path("/proc/self/status")
                .read_text(encoding="utf-8")
                .splitlines()
                if line.startswith("VmHWM:")
            )
        ),
    }
    (target / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    (target / "differences.json").write_text(
        json.dumps(differences, indent=2), encoding="utf-8"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/codec-diff"))
    parser.add_argument(
        "--worker", nargs=4, metavar=("LIBRARY", "LABEL", "KIND", "INPUT")
    )
    args = parser.parse_args()
    for module in ("cramjam", "unpackio"):
        importlib.import_module(module)
    if args.worker:
        library, label, kind, source = args.worker
        worker(library, label, kind, Path(source).read_bytes(), args.output)
        return
    args.output.mkdir(parents=True, exist_ok=True)
    cases = [
        (lib, kind, kind, encode(kind, payload(2048)))
        for lib, kinds in (("cramjam", CRAMJAM), ("unpackio", UNPACKIO + CONTAINERS))
        for kind in kinds
        if kind not in ("snappy", "snappy_raw")
    ]
    cases += [
        ("unpackio", label, kind, data)
        for label, (kind, data) in fixture_cases().items()
    ]
    summaries, differences = [], []
    for library, label, kind, data in cases:
        folder = args.output / f"{library}-{label}"
        folder.mkdir(exist_ok=True)
        source = folder / "valid.bin"
        source.write_bytes(data)
        command = [
            sys.executable,
            __file__,
            "--output",
            str(folder),
            "--worker",
            library,
            label,
            kind,
            str(source),
        ]
        try:
            process = subprocess.run(
                command, capture_output=True, timeout=60, check=False
            )
            if process.returncode:
                summary = {
                    "library": library,
                    "label": label,
                    "worker_exit": process.returncode,
                    "stderr": process.stderr.decode(errors="replace"),
                }
            else:
                summary = json.loads(
                    (folder / "summary.json").read_text(encoding="utf-8")
                )
                for item in json.loads(
                    (folder / "differences.json").read_text(encoding="utf-8")
                ):
                    item["input"] = f"{folder.name}/{item['input']}"
                    differences.append(item)
        except subprocess.TimeoutExpired:
            summary = {"library": library, "label": label, "timeout": True}
        summaries.append(summary)
        print(library, label, summary.get("counts", summary), flush=True)
    for name, value in (("summary", summaries), ("differences", differences)):
        (args.output / f"{name}.json").write_text(
            json.dumps(value, indent=2), encoding="utf-8"
        )
    print("PID", os.getpid(), "results", args.output)


if __name__ == "__main__":
    main()
