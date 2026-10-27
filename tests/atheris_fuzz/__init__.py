"""Coverage-guided Atheris fuzz harness (threat-model O5 / testing-contract).

Not collected by the default pytest matrix. Run via::

    uv sync --group fuzz --group dev --extra all
    uv run --no-sync python -m tests.atheris_fuzz --smoke
"""

from __future__ import annotations

__all__ = ["DEFAULT_BUDGETS", "TARGET_NAMES"]

# Default full / nightly partition (~4–5+ min). Overridable via ARCHIVEY_FUZZ_BUDGET_<NAME>.
# CI PR jobs set shorter env budgets; local defaults match the nightly depth.
# Keep header slices well-fed; stream/codec slices are required (not dropped to fit).
DEFAULT_BUDGETS: dict[str, int] = {
    "sevenzip_header": 45,
    "sevenzip_open": 20,
    "detect_format": 12,
    "zip": 25,
    "tar": 10,
    "iso": 8,
    "rar_header": 30,
    "rar": 15,
    # Auto-detect open: SFX payload offset, single-file reader, compressed tar, UDIF.
    "open_detected": 20,
    # BCJ2, ARM64, Delta and the liblzma branch filters, fed directly.
    "filters": 15,
    "unix_compress": 15,
    "xz": 12,
    "lzip": 10,
    "gzip": 10,
    "bzip2": 10,
    "lzma_alone": 8,
    "zlib": 8,
    "zstd": 8,
    "brotli": 8,
    "lz4": 8,
    "deflate64": 8,
    # Accelerators forced on, compared with the accelerators-off decode. Each input
    # decodes twice, and the gzip family starts a child process, so these run slower.
    "gzip_accel": 15,
    "zlib_accel": 10,
    "deflate_accel": 10,
    "bzip2_accel": 15,
}

TARGET_NAMES: tuple[str, ...] = tuple(DEFAULT_BUDGETS)
