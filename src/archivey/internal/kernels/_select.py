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
  runs in this process, a decoding kernel (ARM64, RISC-V, LZW, LZO1X, LZX) runs in the
  decoder child (:mod:`archivey.internal.kernels.child`), and the Python twin decodes
  when no child can run it. BCJ2 is not run there yet, so the Python twin decodes it.
  CRC-16/ARC and ZipCrypto run in this process under every setting, as checksums and
  AES do.

A missed check in a kernel panics, and PyO3 raises ``pyo3_runtime.PanicException``, a
``BaseException`` that passes ``except Exception``. :func:`panic_to_corruption` turns it
into archivey's ``CorruptionError`` with the panic as its cause.
"""

from __future__ import annotations

import contextlib
from collections.abc import Generator, Mapping
from types import ModuleType
from typing import NoReturn

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
    "lzo1x": 1,
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


def caused_by_panic(exc: BaseException) -> bool:
    """Whether a panic is in ``exc``'s ``__cause__`` chain: the error is a kernel bug,
    never something the archive's data or a password could cause."""
    seen: set[int] = set()
    cause = exc.__cause__
    while cause is not None and id(cause) not in seen:
        if is_panic(cause):
            return True
        seen.add(id(cause))
        cause = cause.__cause__
    return False


@contextlib.contextmanager
def panic_to_corruption(kernel: str) -> Generator[None]:
    """Raise a panic in the block as ``CorruptionError``, the panic its cause."""
    try:
        yield
    except BaseException as exc:
        if is_panic(exc):
            raise CorruptionError(
                f"archivey-codecs' {kernel} decoder failed on this data: {exc}"
            ) from exc
        raise


@contextlib.contextmanager
def codec_errors(module: Kernels, kernel: str) -> Generator[None]:
    """Raise the package's errors as archivey's, with the same message, and a panic
    as ``CorruptionError``. The kernels raise with their Python twin's message, so the
    error a caller sees is the one the twin raises."""
    try:
        with panic_to_corruption(kernel):
            yield
    except module.TruncatedDataError as exc:
        raise TruncatedError(str(exc)) from None
    except module.CorruptDataError as exc:
        raise CorruptionError(str(exc)) from None
    except module.UnsupportedDataError as exc:
        raise UnsupportedFeatureError(str(exc)) from None


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

    @contextlib.contextmanager
    def guard(self) -> Generator[None]:
        """Raise the stored failure, else run the block, storing a panic in it as
        the ``CorruptionError`` it raises."""
        if self._failure is not None:
            self._raise_again(*self._failure)
        try:
            with panic_to_corruption(self._kernel):
                yield
        except CorruptionError as exc:
            if caused_by_panic(exc) and exc.__cause__ is not None:
                self._failure = (unraised(exc), unraised(exc.__cause__))
            raise

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
