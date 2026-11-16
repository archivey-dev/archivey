"""Free-threaded import and simple roundtrip probe; no concurrency claim."""

from __future__ import annotations

import json
import sys


def main():
    before = sys._is_gil_enabled() if hasattr(sys, "_is_gil_enabled") else None
    import compress_utils as cu
    import py_snappy
    import python_snappy
    import snappy

    data = b"abc" * 100
    results = {
        "compress-utils": cu.decompress(cu.compress(data, "zstd"), "zstd") == data,
        "python-snappy": snappy.decompress(snappy.compress(data)) == data,
        "py-snappy": py_snappy.decompress(py_snappy.compress(data)) == data,
        "python-snappy-pure": python_snappy.decompress(python_snappy.compress(data))
        == data,
    }
    print(
        json.dumps(
            {
                "python": sys.version,
                "gil_before": before,
                "gil_after": sys._is_gil_enabled()
                if hasattr(sys, "_is_gil_enabled")
                else None,
                "results": results,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
