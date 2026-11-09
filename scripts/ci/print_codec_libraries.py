#!/usr/bin/env python3
"""Print the C libraries behind the interpreter's stdlib codecs.

python-distributions.yml runs this on each distribution's Python, so a failure there
can be read against the library versions that leg actually had. liblzma has no Python
attribute for its version: it is read from ``lzma_version_string`` in the ``_lzma``
extension, which works where that extension is a shared library that exports it (not
on Windows, where it is linked in statically).
"""

from __future__ import annotations

import ctypes
import platform
import ssl
import sys
import zlib


def liblzma_version() -> str:
    try:
        import _lzma

        lib = ctypes.CDLL(_lzma.__file__)
        lib.lzma_version_string.restype = ctypes.c_char_p
        return lib.lzma_version_string().decode()
    except (ImportError, OSError, AttributeError) as exc:
        return f"unknown ({type(exc).__name__})"


def main() -> int:
    print("python ", sys.version.replace("\n", " "))
    print("prefix ", sys.base_prefix)
    print("system ", platform.platform())
    print("zlib   ", zlib.ZLIB_RUNTIME_VERSION)
    print("liblzma", liblzma_version())
    print("openssl", ssl.OPENSSL_VERSION)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
