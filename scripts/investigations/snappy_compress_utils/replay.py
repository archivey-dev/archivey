"""Replay every saved acceptance/output difference; exceptions remain observations.

A successful run means that saved observations reproduced. It does not mean parity.
"""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

from common import archivey_decode, decode, reference
from differential import candidate_decode, observe


def equivalent(a, b):
    if a.get("accepted") != b.get("accepted"):
        return False
    return (
        a.get("sha256") == b.get("sha256")
        if a.get("accepted")
        else a.get("error") == b.get("error")
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--all",
        action="store_true",
        help="Replay the complete saved set (also the default)",
    )
    p.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent)
    args = p.parse_args()
    root = args.directory
    count = 0
    changed = []
    with zipfile.ZipFile(root / "results/differences.zip") as archive:
        for name in archive.namelist():
            if not name.endswith("/differences.json"):
                continue
            for row in json.loads(archive.read(name)):
                data = archive.read(str(Path(name).parent / row["input"]))
                kind = row["kind"]
                size = row["size_argument"]
                a = observe(
                    lambda data=data, kind=kind, size=size: (
                        reference(kind, data)
                        if kind in ("raw", "framed", "hadoop")
                        else archivey_decode(kind, data, size=size)
                    )
                )
                b = observe(
                    lambda data=data, kind=kind, row=row, size=size: candidate_decode(
                        row["package"], kind, row["mode"], data, size
                    )
                )
                count += 1
                if not equivalent(a, row["reference"]) or not equivalent(
                    b, row["candidate"]
                ):
                    changed.append((name, row["input"], a, b))
    for row in json.loads((root / "results/probes.json").read_text())["cases"]:
        data = (root / "repros" / row["input"]).read_bytes()
        kind = row["kind"]
        a = observe(lambda data=data, kind=kind: reference(kind, data))
        b = observe(
            lambda data=data, kind=kind, row=row: decode(row["package"], kind, data)
        )
        count += 1
        if not equivalent(a, row["reference"]) or not equivalent(b, row["candidate"]):
            changed.append((row["input"], a, b))
    for row in json.loads((root / "results/archivey-corpus.json").read_text())[
        "differences"
    ]:
        data = (root / "repros" / row["input"]).read_bytes()
        a = observe(
            lambda data=data, row=row: archivey_decode("lzo", data, size=row["limit"])
        )
        b = observe(
            lambda data=data, row=row: decode(
                "compress-utils", "lzo", data, size=row["limit"]
            )
        )
        count += 1
        if not equivalent(a, row["reference"]) or not equivalent(b, row["candidate"]):
            changed.append((row["input"], a, b))
    print(json.dumps({"observations_replayed": count, "changed": changed}, indent=2))
    raise SystemExit(bool(changed))


if __name__ == "__main__":
    main()
