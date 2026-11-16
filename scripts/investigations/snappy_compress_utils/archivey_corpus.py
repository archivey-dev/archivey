"""Compare candidate LZO blocks on archivey's own decoder tests, retaining baseline behavior."""

from __future__ import annotations

import argparse
import json
import resource
from pathlib import Path

from common import ROOT
from differential import observe


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--output", type=Path, default=Path("work/archivey-candidate-corpus")
    )
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    import compress_utils as cu
    import pytest

    from archivey.internal.streams.codecs import lzo_decoder

    original = lzo_decoder.lzo1x_decompress_python
    rows = []
    differences = []

    def compare(data, limit):
        expected = observe(lambda data=data: original(data, limit))
        got = observe(lambda data=data: cu.decompress(data, "lzo", expected_size=limit))
        differs = got["accepted"] != expected["accepted"] or (
            got["accepted"] and got["sha256"] != expected["sha256"]
        )
        row = {
            "limit": limit,
            "reference": expected,
            "candidate": got,
            "differs": differs,
        }
        rows.append(row)
        if differs:
            row["input"] = f"lzo-{len(differences)}.bin"
            (args.output / row["input"]).write_bytes(data)
            differences.append(row)
        return original(data, limit)

    lzo_decoder.lzo1x_decompress_python = compare
    try:
        # Instrumentation allocates its own JSON records, so omit the tracemalloc
        # assertion.
        code = pytest.main(
            [
                "-q",
                str(ROOT / "tests/test_lzo.py"),
                "-k",
                "not over_long_match",
                f"--junitxml={args.output / 'tests.xml'}",
            ]
        )
    finally:
        lzo_decoder.lzo1x_decompress_python = original
    (args.output / "archivey-corpus.json").write_text(
        json.dumps(
            {
                "pytest_exit": int(code),
                "calls": len(rows),
                "differences": differences,
                "observations": rows,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(len(rows), "calls;", len(differences), "differences")


if __name__ == "__main__":
    main()
