"""API, checksum, metadata and first-output probes absent from throughput tests.

uv run --with cramjam==2.14.0 --with unpackio==0.1.1 python \
    scripts/investigations/codec_libraries/probes.py --output work/codec-probes

Saved .bin files are crafted or derived from archivey's existing fixture corpus.
No native function receives mutable or immutable output aliasing in these probes.
"""

from __future__ import annotations

import argparse
import io
import json
import resource
import struct
import subprocess
import zipfile
from pathlib import Path

import cramjam
import unpackio
from backports import zstd
from common import CRAMJAM, baseline, candidate, encode, payload
from differential import observe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/codec-probes"))
    parser.add_argument("--sevenzip", type=Path, help="Optional independent 7zz oracle")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = {"incremental": [], "checksums": [], "names": [], "bounds": []}
    raw = payload(2048)
    for kind in CRAMJAM:
        if kind in ("snappy_raw", "lz4_block"):
            continue
        module = getattr(cramjam, "xz" if kind == "lzma_alone" else kind)
        data = encode(kind, raw)

        def split_decode(module=module, data=data):
            decoder = module.Decompressor()
            middle = len(data) // 2
            decoder.decompress(data[:middle])
            first = bytes(decoder.flush())
            decoder.decompress(data[middle:])
            return first + bytes(decoder.finish())

        results["incremental"].append(
            {
                "kind": kind,
                "split": observe(split_decode),
                "output_len_8": observe(
                    lambda m=module, b=data: bytes(m.decompress(b, output_len=8))
                ),
            }
        )
    # CRC/checksum bytes, not arbitrary payload bits. No payload checksum in raw
    # DEFLATE/Brotli/.Z.
    checks = [
        (kind, encode(kind, raw), offset)
        for kind, offset in (("gzip", -8), ("zlib", -1), ("bzip2", -3), ("lz4", -1))
    ]
    xz_data = encode("xz", raw)
    index_bytes = (int.from_bytes(xz_data[-8:-4], "little") + 1) * 4
    checks.append(("xz", xz_data, len(xz_data) - 12 - index_bytes - 1))
    checks.append(
        (
            "zstd",
            zstd.compress(raw, options={zstd.CompressionParameter.checksum_flag: 1}),
            -1,
        )
    )
    checks.append(("snappy", encode("snappy", raw), 14))
    for kind, data, offset in checks:
        damaged = bytearray(data)
        damaged[offset] ^= 1
        path = args.output / f"bad-check-{kind}.bin"
        path.write_bytes(damaged)
        row = {
            "kind": kind,
            "input": path.name,
            "cramjam": observe(
                lambda k=kind, b=bytes(damaged): candidate("cramjam", k, b)
            ),
        }
        if kind != "snappy":
            row["archivey"] = observe(lambda k=kind, b=bytes(damaged): baseline(k, b))
        if kind in ("lz4", "zstd"):
            row["unpackio"] = observe(
                lambda k=kind, b=bytes(damaged): candidate("unpackio", k, b)
            )
        results["checksums"].append(row)
    # ZIP path metadata is advisory; neither inspect nor extract-to-writer applies it to
    # disk.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as out:
        for name in (
            "/absolute",
            "../escape",
            "a/../../escape",
            "C:\\drive",
            "ok/file",
        ):
            out.writestr(zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0)), b"x")
        link = zipfile.ZipInfo("link", date_time=(2020, 1, 1, 0, 0, 0))
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        out.writestr(link, b"../../escape")
    path = args.output / "hostile-names.zip"
    path.write_bytes(buffer.getvalue())
    archive = unpackio.open_zip_bytes(buffer.getvalue())
    for entry in archive.entries():
        target = io.BytesIO()
        archive.extract_entry_to(entry.index, target)
        results["names"].append(
            {
                "name": entry.name,
                "safe": entry.is_safe_path,
                "reason": entry.unsafe_path_reason,
                "symlink": entry.is_symlink,
                "bytes": target.getvalue().hex(),
            }
        )
    # A fixed buffer bounds writes but does not offer resumable decompression or EOF
    # status.
    for kind in ("gzip", "zlib", "deflate", "bzip2", "xz", "zstd", "lz4", "brotli"):
        module = getattr(cramjam, kind)
        output = bytearray(8)
        try:
            answer = module.decompress_into(encode(kind, raw), output)
            result = {"returned": answer}
        except Exception as exc:  # noqa: BLE001 - observed API failure
            result = {"error": type(exc).__name__, "message": str(exc)}
        results["bounds"].append(
            {"kind": kind, "into_8": result, "output_hex": output.hex()}
        )
    # py7zr Brotli is a real supported archivey producer, refused by unpackio 0.1.1.
    data = encode("7z_brotli", raw)
    (args.output / "py7zr-brotli.7z").write_bytes(data)
    results["brotli_7z"] = {
        "archivey": observe(lambda: baseline("7z_brotli", data)),
        "unpackio": observe(lambda: candidate("unpackio", "7z_brotli", data)),
    }
    import lz4.block

    block = lz4.block.compress(raw, store_size=False)
    legacy = struct.pack("<II", 0x184C2102, len(block)) + block
    (args.output / "legacy-lz4.bin").write_bytes(legacy)
    results["legacy_lz4"] = {
        "archivey": observe(lambda: baseline("lz4", legacy)),
        "cramjam": observe(lambda: candidate("cramjam", "lz4", legacy)),
        "unpackio": observe(lambda: candidate("unpackio", "lz4", legacy)),
    }
    ppmd_raw = payload(262144)
    ppmd_data = encode("7z_ppmd", ppmd_raw)
    ppmd_path = args.output / "ppmd-valid-refused.7z"
    ppmd_path.write_bytes(ppmd_data)
    results["valid_ppmd"] = {
        "input": ppmd_path.name,
        "archivey": observe(lambda: baseline("7z_ppmd", ppmd_data)),
        "unpackio": observe(lambda: candidate("unpackio", "7z_ppmd", ppmd_data)),
    }
    if args.sevenzip:
        import hashlib

        process = subprocess.run(
            [str(args.sevenzip), "x", "-so", str(ppmd_path)],
            capture_output=True,
            timeout=60,
            check=False,
        )
        version = subprocess.run(
            [str(args.sevenzip), "i"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        results["valid_ppmd"]["sevenzip"] = {
            "exit": process.returncode,
            "size": len(process.stdout),
            "sha256": hashlib.sha256(process.stdout).hexdigest(),
            "expected_sha256": hashlib.sha256(ppmd_raw).hexdigest(),
            "banner": version.stdout.splitlines()[:4],
            "stderr": process.stderr.decode(errors="replace"),
        }
    results["peak_rss_kib"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    (args.output / "probes.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
