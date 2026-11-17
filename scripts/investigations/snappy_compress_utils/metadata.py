"""Snapshot exact PyPI releases and optionally download/extract hash-checked sdists."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSIONS = {
    "aff4-snappy": "0.5.1",
    "py-snappy": "0.1.0a1",
    "python-snappy": "0.7.3",
    "python-snappy-pure": "0.2.0",
    "pysnappy": "0.8.2",
    "compress-utils": "0.12.1",
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=Path("work/snappy-upstream"))
    p.add_argument("--download-sources", action="store_true")
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    for name, version in VERSIONS.items():
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{name}/json", timeout=30
        ) as response:
            data = json.load(response)
        (args.output / (name + "-pypi.json")).write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
        if not args.download_sources:
            continue
        files = data["releases"][version]
        for f in files:
            if f["packagetype"] != "sdist":
                continue
            with urllib.request.urlopen(f["url"], timeout=30) as response:
                blob = response.read()
            if hashlib.sha256(blob).hexdigest() != f["digests"]["sha256"]:
                raise ValueError("sdist digest mismatch")
            path = args.output / f["filename"]
            path.write_bytes(blob)
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    # Reject traversal before extraction, including backslash paths on
                    # Windows.
                    for member in archive.namelist():
                        parts = member.replace("\\", "/").split("/")
                        if (
                            ".." in parts
                            or member.startswith(("/", "\\"))
                            or ":" in parts[0]
                        ):
                            raise ValueError("unsafe sdist path")
                    archive.extractall(args.output)
            else:
                with tarfile.open(path) as archive:
                    archive.extractall(args.output, filter="data")
        print(name, version, len(files), "artifacts")


if __name__ == "__main__":
    main()
