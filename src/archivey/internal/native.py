"""archivey-codecs: Rust versions of decoders archivey also has in Python.

When the package is installed, a call site asks here for a kernel by its name in
``archivey_codecs.KERNELS`` and gets it, or ``None`` and uses its Python twin. The two
give the same bytes and raise the same errors (the package's parity tests compare them),
so the choice changes speed only. Design: openspec change ``rust-codecs-package``, D4
(revisions) and D5 (installing and turning it off).

A kernel is used when all of these hold:

- the call's ``FormatPolicy`` does not turn ``OptionalLibrary.ARCHIVEY_CODECS`` off
  (``exclude_libraries`` or ``only_libraries``), the only switch;
- the package is installed and imports;
- its ``KERNELS`` revision for that kernel is at least :data:`MIN_REVISIONS`' (an older
  one may differ from this archivey's Python twin, so it is skipped, logged once at
  DEBUG).

A missed check in a kernel panics, and PyO3 raises ``pyo3_runtime.PanicException``, a
``BaseException`` that passes ``except Exception``. :func:`panic_to_corruption` turns it
into archivey's ``CorruptionError`` with the panic as its cause.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Generator
from types import ModuleType
from typing import Protocol

from archivey.exceptions import CorruptionError
from archivey.internal import logs
from archivey.internal.streams.codecs import deps
from archivey.types import OptionalLibrary

MIN_REVISIONS: dict[str, int] = {
    "crc16_arc": 1,
    "zipcrypto": 1,
}
"""The oldest revision of each kernel this archivey uses: the one whose output and
errors match its Python twin. A kernel not named here is not used."""

# Kernels already logged as too old, so each is logged once per process.
_too_old_logged: set[str] = set()


def kernels(name: str, excluded: frozenset[OptionalLibrary]) -> ModuleType | None:
    """The ``archivey_codecs`` module when its ``name`` kernel is to be used for a
    call whose policy turns off ``excluded``, else ``None``."""
    if OptionalLibrary.ARCHIVEY_CODECS in excluded:
        return None
    module = deps.archivey_codecs.load()
    if module is None:
        return None
    table = getattr(module, "KERNELS", None)
    have = table.get(name) if table is not None else None
    need = MIN_REVISIONS[name]
    if not isinstance(have, int) or have < need:
        if name not in _too_old_logged:
            _too_old_logged.add(name)
            logs.streams.debug(
                "archivey-codecs has %r kernel revision %r; archivey needs %d or "
                "newer, so it uses its Python decoder for it",
                name,
                have,
                need,
            )
        return None
    return module


def is_panic(exc: BaseException) -> bool:
    """Whether ``exc`` is a Rust panic raised by PyO3."""
    kind = type(exc)
    return kind.__name__ == "PanicException" and kind.__module__ == "pyo3_runtime"


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


# ── CRC-16/ARC ────────────────────────────────────────────────────────────────────────


def crc16_arc(
    excluded: frozenset[OptionalLibrary],
) -> Callable[[bytes | bytearray | memoryview, int], int] | None:
    """The kernel's ``crc16_arc(data, crc)``, or ``None`` to use the Python one."""
    module = kernels("crc16_arc", excluded)
    if module is None:
        return None
    native = module.crc16_arc

    def crc16(data: bytes | bytearray | memoryview, crc: int = 0) -> int:
        with panic_to_corruption("CRC-16"):
            return native(data, crc)

    return crc16


# ── ZipCrypto ─────────────────────────────────────────────────────────────────────────


class CipherState(Protocol):
    """A ZipCrypto key state: Python's ``ZipCryptoKeys`` or :class:`NativeZipCrypto`."""

    def copy(self) -> CipherState: ...

    def decrypt(self, data: bytes) -> bytes: ...


class _Decryptor(Protocol):
    """``archivey_codecs.zipcrypto.Decryptor``."""

    def copy(self) -> _Decryptor: ...

    def decrypt(self, data: bytes) -> bytes: ...


class NativeZipCrypto:
    """archivey-codecs' ZipCrypto decryptor, in the shape of ``ZipCryptoKeys``."""

    __slots__ = ("_decryptor",)

    def __init__(self, decryptor: _Decryptor) -> None:
        self._decryptor = decryptor

    def copy(self) -> NativeZipCrypto:
        with panic_to_corruption("ZipCrypto"):
            return NativeZipCrypto(self._decryptor.copy())

    def decrypt(self, data: bytes) -> bytes:
        with panic_to_corruption("ZipCrypto"):
            return self._decryptor.decrypt(data)


def zipcrypto(
    excluded: frozenset[OptionalLibrary],
) -> Callable[[bytes], NativeZipCrypto] | None:
    """A constructor of key states from a password, or ``None`` to use
    ``ZipCryptoKeys``."""
    module = kernels("zipcrypto", excluded)
    if module is None:
        return None
    decryptor = module.zipcrypto.Decryptor

    def new(password: bytes) -> NativeZipCrypto:
        with panic_to_corruption("ZipCrypto"):
            return NativeZipCrypto(decryptor(password))

    return new
