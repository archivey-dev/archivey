"""The optional packages a codec decodes faster with, for ``FormatAvailability.faster_with``.

Each package here only speeds a decode up: without it archivey decodes the same data
in Python, or with the standard library, and gets the same bytes. So none of them can
make a format unreadable, and ``format_availability`` lists an absent one in
``faster_with``, never in ``missing``.

A codec reports them through :meth:`StreamCodec.missing_speedups
<archivey.internal.streams.codecs.base.StreamCodec.missing_speedups>`, which calls
:func:`missing_speedup` once per job: Snappy has two, its block decoder and its CRC.
"""

from __future__ import annotations

import platform
import sys

from archivey.config import AcceleratorMode, ArchiveyConfig, ProcessIsolation
from archivey.internal.excluded_libraries import as_reported
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.rapidgzip_select import rapidgzip_requirement
from archivey.types import MissingComponent, OptionalLibrary

RECOMMENDED_HINT = "pip install archivey[recommended]"


def _cpython() -> bool:
    return sys.implementation.name == "cpython"


def _compress_utils_hint() -> str:
    """``[recommended]`` installs compress-utils only where it has a wheel: CPython,
    except on Intel macOS (pyproject.toml's marker). Elsewhere it builds from source,
    so the hint names the package on its own."""
    intel_mac = sys.platform == "darwin" and platform.machine() != "arm64"
    if _cpython() and not intel_mac:
        return RECOMMENDED_HINT
    return "pip install compress-utils"


def _crc32c_hint() -> str:
    """``[recommended]`` installs google-crc32c on CPython only (pyproject.toml)."""
    return RECOMMENDED_HINT if _cpython() else "pip install google-crc32c"


def rapidgzip_speedup() -> MissingComponent:
    """rapidgzip: parallel decoding of large gzip, zlib, DEFLATE and bzip2 data. The
    component its ``AcceleratorMode.ON`` error names, so the two cannot drift."""
    return rapidgzip_requirement()


def compress_utils_speedup(used_for: str) -> MissingComponent:
    """compress-utils: native LZO1X and Snappy block decoding."""
    return MissingComponent(
        OptionalLibrary.COMPRESS_UTILS, _compress_utils_hint(), (used_for,)
    )


def crc32c_speedup() -> MissingComponent:
    """google-crc32c: a native CRC-32C for Snappy chunks."""
    return MissingComponent(
        OptionalLibrary.GOOGLE_CRC32C, _crc32c_hint(), ("snappy crc",)
    )


def cramjam_speedup() -> MissingComponent:
    """cramjam: native Snappy block decoding, used when compress-utils is not."""
    return MissingComponent(OptionalLibrary.CRAMJAM, "pip install cramjam", ("snappy",))


def crc32c_fallback_speedup() -> MissingComponent:
    """crc32c: a native CRC-32C for Snappy chunks, used when google-crc32c is not."""
    return MissingComponent(
        OptionalLibrary.CRC32C, "pip install crc32c", ("snappy crc",)
    )


def missing_snappy_native(
    excluded: frozenset[OptionalLibrary],
) -> tuple[MissingComponent, ...]:
    """Snappy's two jobs, each faster with either of two packages: the raw-block
    decoder and the CRC-32C. Without them both run in Python."""
    libraries = deps.snappy_libraries
    return missing_speedup(
        (
            (
                compress_utils_speedup("snappy"),
                libraries[OptionalLibrary.COMPRESS_UTILS],
            ),
            (cramjam_speedup(), libraries[OptionalLibrary.CRAMJAM]),
        ),
        excluded,
    ) + missing_speedup(
        (
            (crc32c_speedup(), libraries[OptionalLibrary.GOOGLE_CRC32C]),
            (crc32c_fallback_speedup(), libraries[OptionalLibrary.CRC32C]),
        ),
        excluded,
    )


def accelerator_used(mode: AcceleratorMode, config: ArchiveyConfig) -> bool:
    """Whether ``config`` would ever decode through rapidgzip with ``mode`` (its
    resolved ``use_rapidgzip`` or ``use_indexed_bzip2``), were it installed: not under ``OFF``,
    and not under ``ProcessIsolation.NONE``, since rapidgzip runs only in a child."""
    return (
        mode is not AcceleratorMode.OFF
        and config.process_isolation is not ProcessIsolation.NONE
    )


def missing_rapidgzip(
    excluded: frozenset[OptionalLibrary],
    mode: AcceleratorMode,
    config: ArchiveyConfig,
) -> tuple[MissingComponent, ...]:
    """rapidgzip, for the deflate family and bzip2 (``mode`` = ``use_rapidgzip``, or for
    bzip2 the deprecated ``use_indexed_bzip2`` while it is set). It decodes large data
    in parallel, in a child process, so a config that never starts one has nothing to
    gain from it."""
    if not accelerator_used(mode, config):
        return ()
    return missing_speedup(((rapidgzip_speedup(), deps.rapidgzip),), excluded)


def missing_lzo_native(
    excluded: frozenset[OptionalLibrary],
) -> tuple[MissingComponent, ...]:
    """compress-utils, for ``.lzo`` files and raw LZO1X blocks. Without it, LZO1X
    decodes in Python, 20 to 30 times slower."""
    return missing_speedup(
        ((compress_utils_speedup("lzo"), deps.compress_utils),), excluded
    )


def missing_speedup(
    options: tuple[tuple[MissingComponent, deps.LazyOptional], ...],
    excluded: frozenset[OptionalLibrary],
) -> tuple[MissingComponent, ...]:
    """One job's speed-up: ``()`` when any package in ``options`` is installed and
    left on by ``excluded``. Any one is enough: Snappy decodes blocks with
    compress-utils or cramjam. Looks each package up without importing it.

    Otherwise the first package ``excluded`` leaves on is reported, with its install
    hint: installing it would help. When ``excluded`` turns every one off, the first
    is reported with the policy as its reason, as a ``missing`` entry is.
    """
    if any(p.available() and p.name not in excluded for _, p in options):
        return ()
    for component, package in options:
        if package.name not in excluded:
            return (component,)
    return (as_reported(options[0][0], excluded),)
