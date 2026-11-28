"""Time a whole ``.lzo`` read through archivey: the Python decoder, compress-utils in
this process, and compress-utils in a child (``NATIVE_DECODERS``).

Needs python-lzo to write the file (the tests' lzop writer compresses with it).
Usage, from anywhere: python pipeline.py
"""

from __future__ import annotations

import io
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from archivey import ArchiveyConfig, FormatPolicy, open_stream  # noqa: E402
from archivey.config import ProcessIsolation  # noqa: E402
from tests.lzop_build import make_lzop  # noqa: E402

SOURCE = b"".join(
    p.read_bytes() for p in sorted((ROOT / "src" / "archivey").rglob("*.py"))
)
DATA = (SOURCE * (16 * 2**20 // len(SOURCE) + 1))[: 16 * 2**20]

CONFIGS = {
    "Python decoder": ArchiveyConfig(
        formats=FormatPolicy(exclude_libraries={"compress_utils"})
    ),
    "compress-utils, in-process": ArchiveyConfig(),
    "compress-utils, NATIVE_DECODERS": ArchiveyConfig(
        process_isolation=ProcessIsolation.NATIVE_DECODERS
    ),
}


def read(blob: bytes, config: ArchiveyConfig) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        with open_stream(io.BytesIO(blob), config=config) as stream:
            assert stream.read() == DATA
        best = min(best, time.perf_counter() - start)
    return best


print("| block size | decoder | MB/s (best of 3, 16 MiB of Python source) |")
print("| ---: | --- | ---: |")
for block in (128 * 1024, 256 * 1024):
    blob = make_lzop(DATA, block_size=block, compress=True)
    for name, config in CONFIGS.items():
        print(
            f"| {block // 1024} KiB | {name} | {len(DATA) / read(blob, config) / 1e6:.0f} |"
        )
