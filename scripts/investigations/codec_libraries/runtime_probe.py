"""Record import/GIL behavior on an explicitly selected interpreter.

uv run --no-project --python 3.14t --with cramjam==2.14.0 python \
    scripts/investigations/codec_libraries/runtime_probe.py --library cramjam

An import probe is not a concurrency stress test or proof of every codec's safety.
Use the same --library option for unpackio where an interpreter-compatible build exists.
"""

import argparse
import importlib
import importlib.metadata
import json
import platform
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", choices=("cramjam", "unpackio"), required=True)
    args = parser.parse_args()
    gil_enabled = getattr(sys, "_is_gil_enabled", lambda: None)
    before = gil_enabled()
    start = time.perf_counter()
    module = importlib.import_module(args.library)
    elapsed = time.perf_counter() - start
    print(
        json.dumps(
            {
                "library": args.library,
                "version": importlib.metadata.version(args.library),
                "python": sys.version,
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
                "gil_before": before,
                "gil_after": gil_enabled(),
                "import_seconds": elapsed,
                "backend": getattr(module, "backend", None),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
