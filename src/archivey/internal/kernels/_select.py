"""Which archivey-codecs kernels a call may use, and the guards around them.

:mod:`archivey.internal.kernels` asks here for a kernel by its name in
``archivey_codecs.KERNELS`` and gets the module (or its stand-in in a decoder child), or
``None`` to use the Python twin. Design: openspec change ``rust-codecs-package``, D4
(revisions) and D5 (installing and turning it off).

A kernel is used when all of these hold:

- the call's ``FormatPolicy`` does not turn ``OptionalLibrary.ARCHIVEY_CODECS`` off
  (``exclude_libraries`` or ``only_libraries``), the one switch a caller sets for it;
- the package is installed and imports;
- its ``KERNELS`` revision for that kernel is at least :data:`MIN_REVISIONS`' (an older
  one may differ from this archivey's Python twin, so it is skipped, logged once at
  DEBUG);
- under ``ProcessIsolation.NATIVE_DECODERS``, which promises that no native decoder
  runs in this process, a decoding kernel (ARM64, RISC-V, LZW, LZO1X, LZX, LZFSE,
  LZVN) runs in the decoder child (:mod:`archivey.internal.kernels.child`), and the
  Python twin decodes when no child can run it. BCJ2 is not run there yet, so its
  Python twin decodes it. CRC-16/ARC and ZipCrypto run in this process under every
  setting, as checksums and AES do.

A missed check in a kernel panics, and PyO3 raises ``pyo3_runtime.PanicException``, a
``BaseException`` that passes ``except Exception``. :func:`panic_to_corruption` turns it
into archivey's ``CorruptionError`` with the panic as its cause.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import ModuleType
from typing import Literal, NoReturn

from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal import logs
from archivey.internal.kernels import child
from archivey.internal.kernels.child import ChildCodecs, ChildPanic
from archivey.internal.streams.codecs import deps
from archivey.internal.streams.kept_errors import unraised
from archivey.types import OptionalLibrary

MIN_REVISIONS: dict[str, int] = {
    "arm64": 1,
    "bcj2": 1,
    "crc16_arc": 1,
    "lzfse": 1,
    "lzo1x": 1,
    "lzvn": 1,
    "lzw": 1,
    "lzx": 2,
    "riscv": 1,
    "zipcrypto": 1,
}
"""The oldest revision of each kernel this archivey uses: the one whose output and
errors match its Python twin. A kernel not named here is not used."""

# Kernels already logged as too old, so each is logged once per process.
_too_old_logged: set[str] = set()


Kernels = ModuleType | ChildCodecs
"""The ``archivey_codecs`` module, or its stand-in whose kernels run in a decoder
child."""


def kernels(name: str, excluded: frozenset[OptionalLibrary]) -> ModuleType | None:
    """The ``archivey_codecs`` module when its ``name`` kernel is to be used in this
    process for a call whose policy turns off ``excluded``, else ``None``."""
    if OptionalLibrary.ARCHIVEY_CODECS in excluded:
        return None
    module = deps.archivey_codecs.load()
    if module is None or not _current(name, getattr(module, "KERNELS", None)):
        return None
    return module


def decoding_kernels(
    name: str, excluded: frozenset[OptionalLibrary], *, isolated: bool
) -> Kernels | None:
    """:func:`kernels` for a decoding kernel. ``isolated``: the call's
    ``process_isolation`` is ``NATIVE_DECODERS``, and the module's stand-in that runs
    each kernel in a decoder child is returned instead
    (:func:`child.open_kernels`)."""
    if not isolated:
        return kernels(name, excluded)
    if OptionalLibrary.ARCHIVEY_CODECS in excluded:
        return None
    module = child.open_kernels(excluded)
    if module is None or not _current(name, module.KERNELS):
        return None
    return module


def _current(name: str, table: Mapping[str, object] | None) -> bool:
    """Whether ``table`` (``KERNELS``) has a revision of ``name`` this archivey uses;
    an older one is logged once at DEBUG."""
    have = table.get(name) if table is not None else None
    need = MIN_REVISIONS[name]
    if isinstance(have, int) and have >= need:
        return True
    if name not in _too_old_logged:
        _too_old_logged.add(name)
        logs.streams.debug(
            "archivey-codecs has %r kernel revision %r; archivey needs %d or "
            "newer, so it uses its Python decoder for it",
            name,
            have,
            need,
        )
    return False


def is_panic(exc: BaseException) -> bool:
    """Whether ``exc`` is a Rust panic raised by PyO3, here or in a decoder child."""
    if isinstance(exc, ChildPanic):
        return True
    kind = type(exc)
    return kind.__name__ == "PanicException" and kind.__module__ == "pyo3_runtime"


def panic_of(exc: BaseException) -> BaseException | None:
    """The panic in ``exc``'s ``__cause__`` chain, or ``None``. A caller that raises a
    new error in place of ``exc`` raises it ``from panic_of(exc)``, so a kernel bug
    keeps its panic as the cause."""
    seen: set[int] = set()
    cause = exc.__cause__
    while cause is not None and id(cause) not in seen:
        if is_panic(cause):
            return cause
        seen.add(id(cause))
        cause = cause.__cause__
    return None


def caused_by_panic(exc: BaseException) -> bool:
    """Whether a panic is in ``exc``'s ``__cause__`` chain: the error is a kernel bug,
    never something the archive's data or a password could cause."""
    return panic_of(exc) is not None


# The guards below are classes, not ``contextlib.contextmanager`` generators. On
# CPython 3.12 a generator keeps the frame that last resumed it as its ``f_back``, so
# when it raises a new error in place of one thrown into it, the thrown error's
# traceback holds the generator's frame, that ``f_back`` is contextlib's ``__exit__``
# frame, and that frame holds the thrown error: a cycle that keeps the caller's frames,
# and the kernel object in them, alive until the garbage collector runs (see
# ``kept_errors``). For the same reason each ``__exit__`` deletes its local for the
# error it raises as the raise leaves: its frame is in that error's traceback.


def _as_corruption(kernel: str, exc: BaseException) -> BaseException:
    """``exc`` as the error to raise: a new ``CorruptionError`` for a panic (the
    caller raises it from the panic), else ``exc`` itself."""
    if is_panic(exc):
        return CorruptionError(
            f"archivey-codecs' {kernel} decoder failed on this data: {exc}"
        )
    return exc


class panic_to_corruption:
    """Raise a panic in the block as ``CorruptionError``, the panic its cause."""

    __slots__ = ("_kernel",)

    def __init__(self, kernel: str) -> None:
        self._kernel = kernel

    def __enter__(self) -> None:
        return None

    def __exit__(
        self, kind: type[BaseException] | None, exc: BaseException | None, tb: object
    ) -> Literal[False]:
        if exc is None:
            return False
        error = _as_corruption(self._kernel, exc)
        if error is exc:
            return False
        try:
            raise error from exc
        finally:
            del error


class codec_errors:
    """Raise the package's errors as archivey's, with the same message, and a panic
    as ``CorruptionError``. The kernels raise with their Python twin's message, so the
    error a caller sees is the one the twin raises."""

    __slots__ = ("_kernel", "_module")

    def __init__(self, module: Kernels, kernel: str) -> None:
        self._module = module
        self._kernel = kernel

    def __enter__(self) -> None:
        return None

    def __exit__(
        self, kind: type[BaseException] | None, exc: BaseException | None, tb: object
    ) -> Literal[False]:
        if exc is None:
            return False
        error = _as_corruption(self._kernel, exc)
        if error is not exc:
            try:
                raise error from exc
            finally:
                del error
        module = self._module
        if isinstance(exc, module.TruncatedDataError):
            raise TruncatedError(str(exc)) from None
        if isinstance(exc, module.CorruptDataError):
            raise CorruptionError(str(exc)) from None
        if isinstance(exc, module.UnsupportedDataError):
            raise UnsupportedFeatureError(str(exc)) from None
        return False


class Latch:
    """The panic a kernel object raised, so that the object refuses every later
    method call: after a panic its state may be half updated, so it decodes nothing
    more. Its counters (``total_in``, ``eof`` and the like) still read, so a caller
    can report where it stopped. Each wrapper of a stateful kernel object holds
    one."""

    __slots__ = ("_failure", "_kernel")

    def __init__(self, kernel: str) -> None:
        self._kernel = kernel
        # Copies never raised of the error and of its panic, not the raised ones: a
        # raised error's traceback holds the frames, and so the wrapper, that hold
        # this latch (see ``kept_errors``).
        self._failure: tuple[CorruptionError, BaseException] | None = None

    def guard(self) -> Latch:
        """The latch as a context manager: it raises the stored failure, else runs
        the block, storing a panic in it as the ``CorruptionError`` it raises. A class
        rather than a generator: see the note above :func:`_as_corruption`."""
        return self

    def __enter__(self) -> None:
        if self._failure is not None:
            self._raise_again(*self._failure)

    def __exit__(
        self, kind: type[BaseException] | None, exc: BaseException | None, tb: object
    ) -> Literal[False]:
        if exc is None:
            return False
        error = _as_corruption(self._kernel, exc)
        if isinstance(error, CorruptionError):
            # The panic itself, wherever it is in the chain: a copy drops its own
            # cause, so a copy of a cause that wraps the panic would lose it.
            panic = exc if error is not exc else panic_of(exc)
            if panic is not None:
                self._failure = (unraised(error), unraised(panic))
            del panic
        if error is exc:
            return False
        try:
            raise error from exc
        finally:
            del error

    @staticmethod
    def _raise_again(error: CorruptionError, panic: BaseException) -> NoReturn:
        """Raise a fresh copy of ``error`` from a fresh copy of ``panic``: the panic
        stays its cause, which ``caused_by_panic`` reads. The locals go as the raise
        leaves, so this frame is not tied to the error."""
        again, cause = unraised(error), unraised(panic)
        again.__traceback__ = cause.__traceback__ = None
        try:
            raise again from cause
        finally:
            del again, cause
