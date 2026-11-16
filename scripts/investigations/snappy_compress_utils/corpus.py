"""Cross-decode py-snappy's Google fixtures with every runnable Snappy package.

Clone https://github.com/ethereum/py-snappy at f91082fa1498ed919ef26bd853a4552675c9665a.
This tests the released packages, independent of the repository's test imports.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import resource
import subprocess
import sys
from pathlib import Path

from common import SNAPPY_PACKAGES, decode, reference
from differential import observe


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--py-snappy-repo", type=Path)
    p.add_argument("--worker", nargs=2)
    p.add_argument("--output", type=Path, default=Path("work/snappy-corpus"))
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    if args.worker:
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        package, path = args.worker
        print(
            json.dumps(observe(lambda: decode(package, "raw", Path(path).read_bytes())))
        )
        return
    if args.py_snappy_repo is None:
        p.error("--py-snappy-repo is required")
    import pysnappy

    rows = []
    for path in sorted((args.py_snappy_repo / "tests/fixtures").iterdir()):
        raw = path.read_bytes()
        bad = path.suffix == ".snappy"
        data = raw if bad else pysnappy.compress(raw)
        expected = observe(lambda data=data: reference("raw", data))
        encoded = args.output / "current-input.bin"
        encoded.write_bytes(data)
        for package in SNAPPY_PACKAGES:
            command = [sys.executable, __file__, "--worker", package, str(encoded)]
            try:
                proc = subprocess.run(
                    command, capture_output=True, text=True, timeout=15, check=False
                )
                got = (
                    json.loads(proc.stdout)
                    if proc.returncode == 0
                    else {"worker_exit": proc.returncode}
                )
            except subprocess.TimeoutExpired:
                got = {"timeout": True}
            differs = got.get("accepted") != expected["accepted"] or (
                got.get("accepted") and got["sha256"] != expected["sha256"]
            )
            rows.append(
                {
                    "fixture": path.name,
                    "package": package,
                    "source_sha256": hashlib.sha256(raw).hexdigest(),
                    "input_size": len(data),
                    "reference": expected,
                    "candidate": got,
                    "differs": differs,
                }
            )
            if differs:
                (args.output / (package + "-" + path.name + ".bin")).write_bytes(data)
            (args.output / "corpus.json").write_text(
                json.dumps(rows, indent=2), encoding="utf-8"
            )
            print(path.name, package, got.get("accepted", got), flush=True)
    (args.output / "corpus.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8"
    )
    print(len(rows), "cross-reads;", sum(r["differs"] for r in rows), "differences")


if __name__ == "__main__":
    main()
