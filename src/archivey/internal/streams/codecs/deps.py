"""The optional packages the codecs use, found once and read at call time.

Codec modules read these as ``deps.zstd`` and so on, never ``from deps import zstd``, so a
test that patches a name here reaches every codec.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from types import ModuleType

from archivey.internal import logs
from archivey.types import OptionalLibrary


# Optional packages: resolved once via importlib (rather than static imports) because
# several of these have no type stubs and are absent in the core-only environment. Absence
# becomes a clear PackageNotInstalledError when the corresponding codec is opened.
def _optional(name: str) -> ModuleType | None:
    try:
        return importlib.import_module(name)
    except (
        ImportError
    ):  # pragma: no cover - the absent path runs in the core-only CI leg
        return None


def _optional_zstd() -> tuple[ModuleType | None, OptionalLibrary | None]:
    """Stdlib ``compression.zstd`` (3.14+) or ``backports.zstd`` (older Pythons), and
    which of the two it is."""
    for name in (OptionalLibrary.COMPRESSION_ZSTD, OptionalLibrary.BACKPORTS_ZSTD):
        try:
            return importlib.import_module(name), name
        except ImportError:
            continue
    return None, None


class LazyOptional:
    """An optional package that is found without importing it, and imported on first use.

    On a free-threaded CPython, importing an extension module that has not declared
    free-thread support re-enables the GIL for the whole process. pyppmd, inflate64,
    brotli and rapidgzip are such modules (measured 2026-10-08 on 3.13t, 3.14t and
    3.15t). Importing them when this module loads would re-enable the GIL for every
    program that imports archivey with them installed, even one that never opens a
    stream they decode. So :meth:`available` only looks the package up, and the import
    waits for :meth:`load`, which a codec calls when it opens a stream that needs it.
    zstd and lz4 keep the GIL disabled and stay eager imports.

    There is no lock: two threads in :meth:`load` at once both get the same module
    (the import system serialises the import), and every field write stores the value
    the other thread would store, so a lost update changes nothing. A new field that is
    not repeat-safe in that way needs a lock.
    """

    def __init__(self, name: OptionalLibrary, *, present: bool | None = None) -> None:
        self.name = name
        # ``present=`` overrides the lookup: ``False`` stands for an absent package
        # (also one archivey does not use here), ``True`` for an installed one (tests).
        self._present = present
        self._module: ModuleType | None = None
        self._import_failed = False

    def available(self) -> bool:
        """Whether the package is installed. Does not import it."""
        if self._present is None:
            try:
                self._present = importlib.util.find_spec(self.name) is not None
            except (ImportError, ValueError):
                self._present = False
        return self._present

    def load(self) -> ModuleType | None:
        """The imported package, or ``None`` if it is absent or fails to import.

        A package that is found but fails to import (a broken wheel, a missing shared
        library) is logged once and then treated as absent, as it was when these were
        imported with this module. Any exception counts: the import runs inside a codec
        open, where an untranslated error from another package would be a surprise.
        """
        if self._module is None and not self._import_failed and self.available():
            try:
                self._module = importlib.import_module(self.name)
            except Exception as exc:  # noqa: BLE001 - any import failure means absent
                self._import_failed = True
                logs.streams.warning(
                    "%r is installed but failed to import (%r); archivey reads as "
                    "if it were absent.",
                    str(self.name),
                    exc,
                )
        return self._module

    def loaded(self) -> ModuleType | None:
        """The package if it has been imported already, else ``None``. Never imports.

        For exception translation: an exception from a package that was never
        imported cannot be one of that package's own types.
        """
        return self._module


# One zstd module per process: excluding it (``FormatPolicy.exclude_libraries``) turns
# zstd off, and excluding the other name changes nothing. backports.zstd does not
# install on 3.14 and later, so the two are not found together.
zstd, zstd_library = _optional_zstd()
# Packages archivey does not use under PyPy, with why. It reads as if they were absent, and
# the reason replaces the install advice wherever a missing package is reported
# (``MissingComponent.reason``). dev-docs/known-issues.md has the symptoms, the versions
# measured and the upstream status. tests/conftest.py keeps its own copy of these names
# (``UNUSED_UNDER_PYPY``), because it must block the imports before archivey loads.
UNDER_PYPY = sys.implementation.name == "pypy"
_UNUSED_UNDER_PYPY: dict[OptionalLibrary, str] = {
    OptionalLibrary.LZ4: "archivey does not use lz4 under PyPy, where its frame decoder crashes the "
    "interpreter",
    OptionalLibrary.PYPPMD: "archivey does not use pyppmd under PyPy, where it returns PPMd data cut "
    "short",
    OptionalLibrary.RAPIDGZIP: "archivey does not use rapidgzip under PyPy, where it misreads valid "
    "streams",
    OptionalLibrary.INFLATE64: "archivey does not use inflate64 under PyPy, where it decodes larger "
    "Deflate64 input wrong or crashes the interpreter",
}


def unused_reason(package: OptionalLibrary) -> str:
    """Why archivey does not use ``package`` on this interpreter although it may be
    installed, or ``""`` when it uses it whenever it is installed."""
    return _UNUSED_UNDER_PYPY.get(package, "") if UNDER_PYPY else ""


_LZ4_UNUSED = bool(unused_reason(OptionalLibrary.LZ4))
lz4_frame = None if _LZ4_UNUSED else _optional("lz4.frame")
lz4_block = None if _LZ4_UNUSED else _optional("lz4.block")
brotli = LazyOptional(OptionalLibrary.BROTLI)
# python-lzo: only an accelerator, since LZO1X decodes in Python without it.
lzo = LazyOptional(OptionalLibrary.LZO)
pyppmd = LazyOptional(
    OptionalLibrary.PYPPMD,
    present=False if unused_reason(OptionalLibrary.PYPPMD) else None,
)
inflate64 = LazyOptional(
    OptionalLibrary.INFLATE64,
    present=False if unused_reason(OptionalLibrary.INFLATE64) else None,
)
# rapidgzip runs in a child process for every codec it decodes (gzip, zlib, raw deflate
# and bzip2), so this process only needs to know it is installed. bzip2 uses rapidgzip's
# bundled IndexedBzip2File, never the separate indexed_bzip2 package: the two loaded into
# one process corrupt the heap on macOS (ADR 0008). Under PyPy it reads as absent, so
# ``ON`` raises the PackageNotInstalledError of an absent package and ``AUTO`` stays
# quiet; ``rapidgzip_child_unavailable_reason`` keeps refusing a child there as well.
rapidgzip = LazyOptional(
    OptionalLibrary.RAPIDGZIP,
    present=False if unused_reason(OptionalLibrary.RAPIDGZIP) else None,
)
