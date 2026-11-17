"""Snapshot PyPI artifacts and Cargo.lock package license declarations.

uv run python scripts/investigations/codec_libraries/metadata.py --output
work/codec-metadata

Downloads release sdists, never runs their build hooks. The license inventory is
an overinclusive LOCKFILE inventory: build, test, platform and disabled-feature
packages are included. It is not a claim that every listed crate is linked into
any wheel, or a legal audit. Registry failures stay explicit in the JSON output.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import io
import json
import tarfile
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

VERSIONS = {"cramjam": "2.14.0", "unpackio": "0.1.1"}


def fetch(url):
    request = urllib.request.Request(
        url, headers={"User-Agent": "archivey-codec-investigation"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def crate_metadata(item):
    name, version = item
    try:
        data = json.loads(fetch(f"https://crates.io/api/v1/crates/{name}/{version}"))[
            "version"
        ]
        return {
            "name": name,
            "version": version,
            "license": data.get("license"),
            "checksum": data.get("checksum"),
        }
    except (urllib.error.URLError, KeyError, TimeoutError) as exc:
        return {"name": name, "version": version, "lookup_error": str(exc)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/codec-metadata"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    locks, metadata, sources = {}, {}, {}
    for name, version in VERSIONS.items():
        data = json.loads(fetch(f"https://pypi.org/pypi/{name}/{version}/json"))
        all_releases = json.loads(fetch(f"https://pypi.org/pypi/{name}/json"))
        releases = sorted(
            (files[0]["upload_time_iso_8601"], v)
            for v, files in all_releases["releases"].items()
            if files
        )
        metadata[name] = {
            "version": version,
            "info": data["info"],
            "files": data["urls"],
            "release_dates": releases,
        }
        sdist = next(f for f in data["urls"] if f["packagetype"] == "sdist")
        blob = fetch(sdist["url"])
        assert hashlib.sha256(blob).hexdigest() == sdist["digests"]["sha256"]
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            lockpath = (
                f"{name}-{version}/Cargo.lock"
                if name == "cramjam"
                else f"{name}-{version}/bindings/python/Cargo.lock"
            )
            stream = archive.extractfile(lockpath)
            assert stream is not None
            lock = tomllib.loads(stream.read().decode())
            locks[name] = [
                (p["name"], p["version"])
                for p in lock["package"]
                if p.get("source", "").startswith("registry+")
            ]
            sources[name] = {
                "sdist_sha256": sdist["digests"]["sha256"],
                "lockfile": lockpath,
            }
    items = sorted({item for lock in locks.values() for item in lock})
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        licenses = list(pool.map(crate_metadata, items))
    by_key = {(item["name"], item["version"]): item for item in licenses}
    inventory = {name: [by_key[item] for item in lock] for name, lock in locks.items()}
    for name, value in (
        ("packaging", metadata),
        ("lockfile-licenses", inventory),
        ("sources", sources),
    ):
        (args.output / f"{name}.json").write_text(
            json.dumps(value, indent=2), encoding="utf-8"
        )
    try:
        result = fetch("https://crates.io/api/v1/crates/unpackio").decode()
    except urllib.error.HTTPError as exc:
        result = f"HTTP {exc.code}: {exc.reason}"
    (args.output / "unpackio-crates-lookup.txt").write_text(
        result + "\n", encoding="utf-8"
    )
    print("Saved", args.output)


if __name__ == "__main__":
    main()
