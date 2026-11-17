"""Replay saved differences without extracting archive member paths to disk.

uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
    scripts/investigations/codec_libraries/replay.py --all

The default replays the first difference per library/kind/outcome. --all checks
every saved input. Exit 1 means an observed acceptance, hash or error CLASS changed
since the recorded release experiment, which warrants investigation. Messages may
change and are printed but not compared. Run against the recorded archivey base.
"""

from __future__ import annotations

import argparse
import json
import zipfile
from pathlib import Path

from common import baseline, candidate
from differential import observe


def signature(result):
    return (result["accepted"], result.get("sha256"), result.get("error"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--match", default="", help="Substring in the saved repro path")
    args = parser.parse_args()
    seen, failures, total = set(), 0, 0
    with zipfile.ZipFile(
        Path(__file__).with_name("results") / "differences.zip"
    ) as saved:
        records = json.loads(saved.read("differences.json"))
        for item in records:
            library = "cramjam" if "cramjam" in item else "unpackio"
            key = library, item["kind"], item["outcome"]
            if args.match not in item["input"] or (not args.all and key in seen):
                continue
            seen.add(key)
            data = saved.read(item["input"])
            ours = observe(lambda k=item["kind"], b=data: baseline(k, b))
            theirs = observe(
                lambda lib=library, k=item["kind"], b=data: candidate(lib, k, b)
            )
            changed = signature(ours) != signature(item["archivey"]) or signature(
                theirs
            ) != signature(item[library])
            failures += changed
            total += 1
            print(
                json.dumps(
                    {
                        "input": item["input"],
                        "changed": changed,
                        "archivey": ours,
                        library: theirs,
                    }
                )
            )
    print(f"{total} repros, {failures} changed outcomes")
    raise SystemExit(bool(failures))


if __name__ == "__main__":
    main()
