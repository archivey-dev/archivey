"""Cross-read the pinned candidates' own shipped fixtures and Python test constructors.

uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
    scripts/investigations/codec_libraries/upstream_corpus.py \
    --sources work/upstream --output work/upstream-corpus

Download/extract the two hash-pinned sdists from results/sources.json first, or use
--download. No build hooks run. This DOES execute unpackio's upstream unittest file
and imports cramjam's streaming test module. Run trusted, pinned release sources only.
Calls made by unpackio's binding suite are captured, deduplicated and then fully read
with both libraries, without its test-specific cancellation/output-limit settings.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import resource
import subprocess
import tarfile
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

import cramjam
import unpackio
import unpackio._native as native
from common import CONFIG, archivey, baseline, candidate
from differential import observe


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def download_sources(target: Path):
    manifest = json.loads(
        Path(__file__)
        .with_name("results")
        .joinpath("sources.json")
        .read_text(encoding="utf-8")
    )
    for name, version in (("cramjam", "2.14.0"), ("unpackio", "0.1.1")):
        with urllib.request.urlopen(
            f"https://pypi.org/pypi/{name}/{version}/json"
        ) as response:
            info = json.load(response)
        artifact = next(f for f in info["urls"] if f["packagetype"] == "sdist")
        with urllib.request.urlopen(artifact["url"]) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != manifest[name]["sdist_sha256"]:
            raise ValueError(f"sdist hash changed: {name}")
        archive_path = target / artifact["filename"]
        archive_path.write_bytes(data)
        with tarfile.open(archive_path) as archive:
            archive.extractall(target, filter="data")


def read_candidate(kind: str, data: bytes, password):
    if kind in ("lz4", "zstd", "unix_compress"):
        return candidate("unpackio", kind, data)
    opener = (
        unpackio.open_bytes if kind == "7z" else getattr(unpackio, f"open_{kind}_bytes")
    )
    kwargs = {} if password is None else {"password": password}
    archive = opener(data, **kwargs)
    output = io.BytesIO()
    for entry in archive.entries():
        if kind == "zip":
            is_file = not entry.is_directory and not entry.is_symlink
        else:
            is_file = entry.kind in ("file", "binary", "text")
        if is_file:
            archive.extract_entry_to(entry.index, output)
    return output.getvalue()


def read_archivey(kind: str, data: bytes, password):
    if kind in ("lz4", "zstd", "unix_compress"):
        return baseline(kind, data)
    with archivey.open_archive(
        io.BytesIO(data), format=kind, password=password, config=CONFIG
    ) as reader:
        pieces = []
        for entry in reader.members():
            if entry.type in (archivey.MemberType.FILE, archivey.MemberType.HARDLINK):
                with reader.open(entry) as stream:
                    pieces.append(stream.read())
        return b"".join(pieces)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=Path("work/upstream"))
    parser.add_argument("--output", type=Path, default=Path("work/upstream-corpus"))
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--cpio", type=Path, help="Optional GNU cpio oracle executable")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    args.output.mkdir(parents=True, exist_ok=True)
    args.sources.mkdir(parents=True, exist_ok=True)
    if args.download:
        download_sources(args.sources)
    rows, captured = [], {}
    current_test = [""]

    class RecordingResult(unittest.TextTestResult):
        def startTest(self, test):
            current_test[0] = test.id()
            super().startTest(test)

    def capture(opener, kind, is_path=False):
        def record(data, *positional, **kwargs):
            if is_path:
                try:
                    blob = Path(data).read_bytes()
                except (OSError, TypeError):
                    blob = None
            else:
                blob = data if isinstance(data, bytes) else None
            if blob is not None and len(blob) <= 32 << 20:
                fmt = kind
                if kind == "stream":
                    selected = kwargs.get("format")
                    fmt = (
                        "lz4"
                        if blob.startswith(b"\x04\x22\x4d\x18")
                        else "zstd"
                        if blob.startswith(b"\x28\xb5\x2f\xfd")
                        else "unix_compress"
                    )
                    if selected in ("lz4", "zstd", "zstandard"):
                        fmt = "zstd" if selected == "zstandard" else selected
                password = kwargs.get("password")
                key = fmt, hashlib.sha256(blob).hexdigest(), repr(password)
                if key not in captured:
                    captured[key] = {
                        "kind": fmt,
                        "data": blob,
                        "password": password,
                        "tests": set(),
                    }
                captured[key]["tests"].add(current_test[0])
            return opener(data, *positional, **kwargs)

        return record

    module = load_module(
        args.sources / "unpackio-0.1.1/bindings/python/tests/test_bindings.py",
        "unpackio_release_binding_tests",
    )
    names = {"open_bytes": "7z", "open_path": "7z"}
    for kind in ("zip", "rpm", "cpio", "deb", "arj", "stream"):
        for suffix in ("bytes", "path"):
            names[f"open_{kind}_{suffix}"] = kind
    fixed_clock = patch(
        "zipfile.time.localtime", return_value=(2020, 1, 1, 0, 0, 0, 2, 1, -1)
    )
    fixed_clock.start()
    patches = [fixed_clock]
    for owner in (unpackio, native):
        for name, kind in names.items():
            if hasattr(owner, name):
                item = patch.object(
                    owner,
                    name,
                    capture(getattr(owner, name), kind, name.endswith("_path")),
                )
                item.start()
                patches.append(item)
    try:
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
        log = io.StringIO()
        result = unittest.TextTestRunner(
            stream=log, verbosity=2, resultclass=RecordingResult
        ).run(suite)
        (args.output / "upstream-unittest.log").write_text(
            log.getvalue(), encoding="utf-8"
        )
        suite_result = {
            "tests": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skipped": len(result.skipped),
        }
    finally:
        for item in reversed(patches):
            item.stop()
    for index, item in enumerate(captured.values()):
        kind, data, password = item["kind"], item["data"], item["password"]
        ours = observe(lambda k=kind, b=data, p=password: read_archivey(k, b, p))
        theirs = observe(lambda k=kind, b=data, p=password: read_candidate(k, b, p))
        outcome = (
            (
                "same_bytes"
                if ours.get("sha256") == theirs.get("sha256")
                else "different_bytes"
            )
            if ours["accepted"] and theirs["accepted"]
            else (
                "both_refuse"
                if not ours["accepted"] and not theirs["accepted"]
                else "candidate_only_accepts"
                if theirs["accepted"]
                else "archivey_only_accepts"
            )
        )
        name = f"unpackio-{index:03d}-{kind}.bin"
        (args.output / name).write_bytes(data)
        rows.append(
            {
                "library": "unpackio",
                "kind": kind,
                "input": name,
                "outcome": outcome,
                "tests": sorted(item["tests"]),
                "archivey": ours,
                "unpackio": theirs,
                "password": (
                    password
                    if isinstance(password, (str, type(None)))
                    else {"base64": base64.b64encode(password).decode()}
                ),
            }
        )
    # Cramjam's committed integration files come from independent codec implementations.
    integration = args.sources / "cramjam-2.14.0/tests/data/integration"
    plain = (integration / "plaintext.txt").read_bytes()
    formats = {
        "gz": "gzip",
        "bz2": "bzip2",
        "lzma": "lzma_alone",
        "br": "brotli",
        "zst": "zstd",
        "lz4": "lz4",
        "snappy": "snappy",
    }
    for suffix, kind in formats.items():
        data = (integration / f"plaintext.txt.{suffix}").read_bytes()
        if suffix == "lzma" and data.startswith(b"\xfd7zXZ\0"):
            kind = (
                "xz"  # Upstream names this fixture .lzma but tests xz auto-detection.
            )
        ours = observe(lambda k=kind, b=data: baseline(k, b))
        theirs = observe(lambda k=kind, b=data: candidate("cramjam", k, b))
        name = f"cramjam-integration-{suffix}.bin"
        (args.output / name).write_bytes(data)
        rows.append(
            {
                "library": "cramjam",
                "kind": kind,
                "input": name,
                "origin": "tests/test_integration.py::test_variant",
                "archivey": ours,
                "cramjam": theirs,
                "expected_sha256": hashlib.sha256(plain).hexdigest(),
            }
        )
    # Exercise the sample/encoder paths from cramjam's own streaming test file.
    streaming = load_module(
        args.sources / "cramjam-2.14.0/tests/test_streaming_semantics.py",
        "cramjam_release_streaming_tests",
    )
    plain = streaming.sample(300_000, 1) + streaming.sample(50_000, 2)
    for kind in ("gzip", "zlib", "deflate", "bzip2", "xz", "lz4", "zstd"):
        encoder = getattr(cramjam, kind).Compressor()
        encoder.compress(plain[:300_000])
        data = bytes(encoder.flush())
        encoder.compress(plain[300_000:])
        data += bytes(encoder.flush()) + bytes(encoder.finish())
        name = f"cramjam-flush-{kind}.bin"
        (args.output / name).write_bytes(data)
        rows.append(
            {
                "library": "cramjam",
                "kind": kind,
                "input": name,
                "origin": (
                    "tests/test_streaming_semantics.py::"
                    "test_compressor_flush_makes_data_available"
                ),
                "archivey": observe(lambda k=kind, b=data: baseline(k, b)),
                "cramjam": observe(lambda k=kind, b=data: candidate("cramjam", k, b)),
                "expected_sha256": hashlib.sha256(plain).hexdigest(),
            }
        )
    # Shipped Rust ARJ fixtures; preserve upstream license notices when saving their
    # bytes.
    for path in sorted(
        (args.sources / "unpackio-0.1.1/crates/unpackio/tests/fixtures/arj").glob(
            "*.b64"
        )
    ):
        data = base64.b64decode(path.read_bytes())
        name = f"unpackio-rust-{path.stem}.bin"
        (args.output / name).write_bytes(data)
        rows.append(
            {
                "library": "unpackio",
                "kind": "arj",
                "input": name,
                "origin": "crates/unpackio/tests/arj_reference.rs",
                "archivey": observe(lambda b=data: read_archivey("arj", b, None)),
                "unpackio": observe(lambda b=data: read_candidate("arj", b, None)),
            }
        )
    triage = {}
    original_string = module.rpm_string
    with patch.object(
        module,
        "rpm_string",
        lambda tag, value: original_string(tag, b"identity" if tag == 1125 else value),
    ):
        identity_rpm = module.rpm_archive()
    (args.output / "rpm-identity-control.bin").write_bytes(identity_rpm)
    triage["identity_rpm"] = {
        "input": "rpm-identity-control.bin",
        "archivey": observe(lambda: read_archivey("rpm", identity_rpm, None)),
        "unpackio": observe(lambda: read_candidate("rpm", identity_rpm, None)),
    }
    if args.cpio:
        mixed = module.cpio_archive()
        uniform = b"".join(
            (
                module.cpio_record(b"070701", b"a", b"hello", 0o100644, 0),
                module.cpio_record(b"070701", b"b", b"world", 0o100644, 0),
                module.cpio_record(b"070701", b"TRAILER!!!", b"", 0, 0),
            )
        )
        triage["gnu_cpio"] = []
        for label, data in (
            ("mixed", mixed),
            ("mixed_padded", mixed + b"\0" * (-len(mixed) % 512)),
            ("uniform_newc", uniform),
        ):
            path = args.output / f"cpio-oracle-{label}.bin"
            path.write_bytes(data)
            process = subprocess.run(
                [str(args.cpio), "-it", "--quiet"],
                input=data,
                capture_output=True,
                timeout=30,
                check=False,
            )
            triage["gnu_cpio"].append(
                {
                    "input": path.name,
                    "exit": process.returncode,
                    "stdout": process.stdout.decode(errors="replace"),
                    "stderr": process.stderr.decode(errors="replace"),
                    "archivey": observe(lambda b=data: read_archivey("cpio", b, None)),
                    "unpackio": observe(lambda b=data: read_candidate("cpio", b, None)),
                }
            )
    report = {"binding_suite": suite_result, "cases": rows, "support_triage": triage}
    (args.output / "upstream-corpus.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    print("Binding suite", suite_result, "cross-read cases", len(rows), flush=True)
    for row in rows:
        ours, theirs = row["archivey"], row[row["library"]]
        if (
            ours.get("sha256") != theirs.get("sha256")
            or ours["accepted"] != theirs["accepted"]
        ):
            print(json.dumps(row), flush=True)


if __name__ == "__main__":
    main()
