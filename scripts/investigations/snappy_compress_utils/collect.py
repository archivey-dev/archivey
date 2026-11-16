"""Collect observations and all differential repros after the documented runs."""

from __future__ import annotations

import argparse
import json
import shutil
import zipfile
from pathlib import Path

from metadata import VERSIONS


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--work", type=Path, default=Path("work"))
    p.add_argument("--destination", type=Path, default=Path(__file__).resolve().parent)
    args = p.parse_args()
    target = args.destination
    results = target / "results"
    repros = target / "repros"
    results.mkdir(parents=True, exist_ok=True)
    repros.mkdir(parents=True, exist_ok=True)
    mappings = {
        "differential-summary.json": "snappy-diff/summary.json",
        "throughput.json": "snappy-bench/throughput.json",
        "memory.json": "snappy-bench/memory.json",
        "imports.json": "snappy-bench/imports.json",
        "probes.json": "snappy-probes/probes.json",
        "upstream.json": "snappy-upstream-results/upstream.json",
        "archivey-corpus.json": "archivey-candidate-corpus/archivey-corpus.json",
        "corpus.json": "snappy-corpus/corpus.json",
        "free-threaded.json": "snappy-free-threaded.json",
    }
    for name, path in mappings.items():
        if (args.work / path).exists():
            shutil.copyfile(args.work / path, results / name)
    for directory in ("snappy-probes", "archivey-candidate-corpus"):
        for path in (args.work / directory).iterdir():
            if path.suffix in (".bin", ".sz"):
                shutil.copyfile(path, repros / path.name)
    packaging = {}
    for name, version in VERSIONS.items():
        data = json.loads(
            (args.work / "snappy-upstream" / f"{name}-pypi.json").read_text()
        )
        info = data["info"]
        releases = data["releases"]
        artifacts = releases[version]
        packaging[name] = {
            "version": version,
            "info": {
                k: info.get(k)
                for k in (
                    "author",
                    "author_email",
                    "license",
                    "license_expression",
                    "requires_python",
                    "requires_dist",
                    "project_urls",
                )
            },
            "release_dates": {
                v: min(f["upload_time_iso_8601"] for f in files)
                for v, files in releases.items()
                if files
            },
            "artifacts": [
                {
                    k: f.get(k)
                    for k in (
                        "filename",
                        "size",
                        "digests",
                        "url",
                        "requires_python",
                        "upload_time_iso_8601",
                    )
                }
                for f in artifacts
            ],
        }
    cu = args.work / "snappy-upstream/compress_utils-0.12.1"
    packaging["compress-utils"]["codec_versions"] = json.loads(
        (cu / "codec-versions.json").read_text()
    )
    (results / "packaging.json").write_text(
        json.dumps(packaging, indent=2), encoding="utf-8"
    )
    with zipfile.ZipFile(
        results / "differences.zip", "w", zipfile.ZIP_DEFLATED
    ) as archive:
        for path in sorted((args.work / "snappy-diff").glob("*/*")):
            if path.suffix in (".bin", ".json"):
                archive.write(
                    path,
                    Path("differential") / path.relative_to(args.work / "snappy-diff"),
                )
        for file in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            if (cu / file).exists():
                archive.write(cu / file, Path("upstream-notices/compress-utils") / file)
    for name in ("aff4-install.log", "py-snappy-tests.log", "py-snappy-error-test.log"):
        if (args.work / name).exists():
            shutil.copyfile(args.work / name, results / name)
    shutil.copyfile(
        args.work / "snappy-upstream-results/tests.log", results / "upstream-tests.log"
    )
    print("collected results and repros in", target)


if __name__ == "__main__":
    main()
