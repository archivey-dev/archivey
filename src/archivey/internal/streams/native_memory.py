"""Native decoder memory on PyPy: what its garbage collector is told, and what a close
frees at once. Every function here is a no-op on CPython.

CPython frees a dropped decoder's native buffers when its last reference goes. PyPy
frees them at a major collection, which only the GC heap's own growth schedules, and a
decoder hardly adds to that heap. A run that drops thousands of decoders (an xz or bzip2
file of many streams, a test suite) then keeps gigabytes of buffers allocated, and once
glibc has grown its heap for them, ``fork`` refuses to copy that mapping:
``subprocess`` raises ``OSError: [Errno 12] Cannot allocate memory``.
``dev-docs/known-issues.md`` §"PyPy: native decoder memory" has the measurements.

Two measures answer it:

- :func:`note_native_memory`: a decoder built in this process reports what it most
  likely holds, which brings the next major collection forward, as PyPy's own
  ``LZMACompressor`` does. The decoders that report are the ones whose library keeps a
  buffer of a MiB or more where PyPy cannot see it: liblzma, libzstd, libbz2 and
  brotli (``codecs/isolated.py``). zlib does not: PyPy accounts for its ``z_stream``
  itself. inflate64's window is 64 KiB, and lz4 is not used under PyPy.
- :func:`end_lzma_decoder`: an estimate cannot see a dictionary that only the stream
  declares (up to 4 GiB with no cap), so a decoder's ``close`` ends its liblzma
  decoders at once (``release_decoder_children``) and cancels the pressure they
  reported. No other library offers that: zstd and brotli are C extensions under PyPy
  with no way to free their state but dropping the object.
"""

from __future__ import annotations

import importlib
import lzma
import sys
from collections.abc import Callable

UNDER_PYPY = sys.implementation.name == "pypy"

# The first PyPy release whose ``zlib`` ``decompressobj.copy()`` frees the inflate state
# it overwrites; ``None`` while no release does (7.3.23 is the latest checked). Every
# earlier PyPy loses about 7 KiB per copy for good: ``rpython/rlib/rzlib.py``'s
# ``inflateCopy`` allocates the copy with ``inflateInit()``, and zlib's ``inflateCopy``
# overwrites that state. A process that reads many archives would grow without bound, so
# where this holds, archivey takes no zlib copy at all (``codecs/deflate_decoder.py``).
_PYPY_ZLIB_COPY_FIXED: tuple[int, int, int] | None = None
ZLIB_COPY_LEAKS = UNDER_PYPY and (
    _PYPY_ZLIB_COPY_FIXED is None
    or tuple(getattr(sys, "pypy_version_info", (0, 0, 0))[:3]) < _PYPY_ZLIB_COPY_FIXED
)

# PyPy's own module; no type checker knows it.
_add_memory_pressure: Callable[[int], None] | None = (
    importlib.import_module("__pypy__").add_memory_pressure if UNDER_PYPY else None
)

# PyPy's ``lzma`` is cffi: a decoder's ``lzs`` is an ``ffi.gc`` handle that calls
# ``lzma_end`` when collected, and ``ffi.release`` calls it now.
_release: Callable[[object], None] | None = (
    getattr(getattr(sys.modules.get("_lzma"), "ffi", None), "release", None)
    if UNDER_PYPY
    else None
)

# Where a liblzma decoder keeps the pressure it reported, for :func:`end_lzma_decoder`
# to cancel. PyPy's ``LZMADecompressor`` is a Python class and takes the attribute.
_NOTED = "_archivey_noted_memory"


def note_native_memory(decoder: object, nbytes: int) -> None:
    """Tell PyPy's GC that ``decoder``, just built, holds ``nbytes`` outside its heap."""
    if _add_memory_pressure is None or nbytes <= 0:
        return
    _add_memory_pressure(nbytes)
    if type(decoder) is lzma.LZMADecompressor:
        setattr(decoder, _NOTED, nbytes)


def end_lzma_decoder(decoder: lzma.LZMADecompressor) -> None:
    """End a liblzma decoder now and cancel the pressure it reported, on PyPy.

    A decoder used after this raises ``LZMAError``: liblzma refuses a stream it has
    ended. A second call does nothing: releasing a released handle is a no-op in cffi
    (measured on PyPy 3.11.17), and the pressure is cancelled once.
    """
    if _release is None:
        return
    handle = getattr(decoder, "lzs", None)
    if handle is not None:
        _release(handle)
    noted = vars(decoder).pop(_NOTED, 0)
    if noted and _add_memory_pressure is not None:
        _add_memory_pressure(-noted)
