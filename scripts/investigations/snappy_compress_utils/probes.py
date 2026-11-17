"""Protocol edge cases, checksum checks, chunk splits and upstream-independent Snappy vectors."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from c_api import BoundedDecoder, framed_decode
from common import (
    SNAPPY_PACKAGES,
    archivey_decode,
    crc32c,
    decode,
    encode,
    payload,
    reference,
)
from differential import observe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("work/snappy-probes"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    rows = []
    raw_cases = {
        "copy4-valid": b"\x05\x00A\x0f\x01\0\0\0",
        "copy-zero-invalid": b"\x04\x01\x00",
        "literal-then-junk": b"\x01\x00A\x00B",
        "empty-raw-missing-length": b"",
        "zero-length-with-junk": b"\x00garbage",
    }
    for name, data in raw_cases.items():
        file = args.output / (name + ".bin")
        file.write_bytes(data)
        expected = observe(lambda b=data: reference("raw", b))
        for package in SNAPPY_PACKAGES:
            rows.append(
                {
                    "case": name,
                    "kind": "raw",
                    "input": file.name,
                    "package": package,
                    "reference": expected,
                    "candidate": observe(lambda p=package, b=data: decode(p, "raw", b)),
                }
            )
    data = encode("framed", payload(2048))
    framed_cases = {
        "missing-identifier": data[10:],
        "bad-crc": data[:14] + bytes([data[14] ^ 1]) + data[15:],
        "unknown-mandatory": data[:10] + b"\x02\0\0\0" + data[10:],
        "skippable": data[:10] + b"\x80\x03\0\0abc" + data[10:],
        "partial-header": data + b"\0",
        "partial-identifier": data[:5],
    }
    oversized = b"A" * 65537
    crc = crc32c(oversized)
    masked = (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF
    body = masked.to_bytes(4, "little") + oversized
    framed_cases["oversized-uncompressed-chunk"] = (
        data[:10] + b"\x01" + len(body).to_bytes(3, "little") + body
    )
    for name, b in framed_cases.items():
        path = args.output / (name + ".sz")
        path.write_bytes(b)
        for package in ("python-snappy", "pysnappy", "cramjam"):
            rows.append(
                {
                    "case": name,
                    "kind": "framed",
                    "input": path.name,
                    "package": package,
                    "reference": observe(lambda d=b: reference("framed", d)),
                    "candidate": observe(lambda p=package, d=b: decode(p, "framed", d)),
                }
            )
    # Explicit multi-subblock Hadoop control, not dependent on an encoder's buffering
    # policy.
    raw = payload(4096)
    a = encode("raw", raw[:2048])
    b = encode("raw", raw[2048:])
    data = struct.pack(">II", 4096, len(a)) + a + struct.pack(">I", len(b)) + b
    path = args.output / "hadoop-multi.bin"
    path.write_bytes(data)
    for package in ("python-snappy", "pysnappy"):
        rows.append(
            {
                "case": "hadoop-multi",
                "kind": "hadoop",
                "input": path.name,
                "package": package,
                "reference": observe(lambda data=data: reference("hadoop", data)),
                "candidate": observe(lambda p=package: decode(p, "hadoop", data)),
            }
        )
    # A true half-input test independent of whether the compressed body exceeds CHUNK.
    import compress_utils as cu
    from common import ALGORITHMS

    incremental = []
    for kind in (
        "gzip",
        "zlib",
        "deflate",
        "bzip2",
        "xz",
        "zstd",
        "lz4",
        "brotli",
        "raw",
    ):
        b = encode(kind, payload(2048))
        decoder = cu.DecompressStream(ALGORITHMS[kind], single_stream=True)

        def split(d=decoder, b=b):
            mid = len(b) // 2
            return d.decompress(b[:mid]) + d.decompress(b[mid:]) + d.finish()

        incremental.append({"kind": kind, "split": observe(split), "eof": decoder.eof})
    drain = []
    for kind in ("gzip", "zlib", "deflate", "bzip2", "xz", "zstd", "lz4", "brotli"):
        b = encode(kind, payload(2048))
        d = BoundedDecoder(kind)
        try:
            out = d.decompress(b + b"TAIL", 17)
            maximum = len(out)
            pieces = [out]
            loops = 0
            while not d.eof:
                block = d.decompress(b"", 17)
                maximum = max(maximum, len(block))
                pieces.append(block)
                loops += 1
                if loops > 10000:
                    raise RuntimeError("no progress")
            drain.append(
                {
                    "kind": kind,
                    "maximum_return": maximum,
                    "bytes": len(b"".join(pieces)),
                    "unused": d.unused_data.hex(),
                    "eof": d.eof,
                }
            )
        finally:
            d.close()
    checksums = []
    # Mutate checksum bytes, not arbitrary data bits whose format may lack integrity.
    for kind, offset in [
        ("gzip", -8),
        ("zlib", -1),
        ("bzip2", -3),
        ("xz", -9),
        ("zstd", -1),
        ("lz4", -1),
    ]:
        b = bytearray(encode(kind, payload(2048)))
        b[offset] ^= 1
        b = bytes(b)
        path = args.output / f"checksum-{kind}.bin"
        path.write_bytes(b)
        checksums.append(
            {
                "kind": kind,
                "reference": observe(lambda b=b, kind=kind: archivey_decode(kind, b)),
                "python": observe(
                    lambda b=b, kind=kind: decode("compress-utils", kind, b)
                ),
                "bounded": observe(lambda b=b, kind=kind: framed_decode(kind, b)),
            }
        )
    (args.output / "probes.json").write_text(
        json.dumps(
            {
                "cases": rows,
                "incremental": incremental,
                "bounded_drain": drain,
                "checksums": checksums,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print("saved", len(rows), "edge cases,", len(checksums), "integrity cases")


if __name__ == "__main__":
    main()
