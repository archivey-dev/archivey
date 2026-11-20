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

from archivey.internal.excluded_libraries import as_reported
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.codecs.rapidgzip_select import _rapidgzip_requirement
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
    return _rapidgzip_requirement()


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


def missing_speedup(
    component: MissingComponent,
    packages: tuple[deps.LazyOptional, ...],
    excluded: frozenset[OptionalLibrary],
) -> tuple[MissingComponent, ...]:
    """``(component,)`` when none of ``packages`` is installed and left on by
    ``excluded``, else ``()``. Any one package is enough: Snappy decodes blocks with
    compress-utils or cramjam. Looks each package up without importing it.

    The reported component carries the policy as its reason when ``excluded`` turns
    it off, as a ``missing`` entry does.
    """
    if any(p.available() and p.name not in excluded for p in packages):
        return ()
    return (as_reported(component, excluded),)
