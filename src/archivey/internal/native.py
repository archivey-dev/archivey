"""archivey-codecs: Rust versions of decoders archivey also has in Python.

When the package is installed, a call site asks here for a kernel by its name in
``archivey_codecs.KERNELS`` and gets it, or ``None`` and uses its Python twin. The two
give the same bytes and raise the same errors (the package's parity tests compare them),
so the choice changes speed only. Design: openspec change ``rust-codecs-package``, D4
(revisions) and D5 (installing and turning it off).

A kernel is used when all of these hold:

- the call's ``FormatPolicy`` does not turn ``OptionalLibrary.ARCHIVEY_CODECS`` off
  (``exclude_libraries`` or ``only_libraries``), the one switch a caller sets for it;
- the package is installed and imports;
- its ``KERNELS`` revision for that kernel is at least :data:`MIN_REVISIONS`' (an older
  one may differ from this archivey's Python twin, so it is skipped, logged once at
  DEBUG);
- for a decoding kernel (ARM64, RISC-V, LZW), the call's ``process_isolation`` is not
  ``NATIVE_DECODERS``: until the decoder child runs these kernels, the Python twin keeps
  that setting's promise that no native decoder runs in this process.

A missed check in a kernel panics, and PyO3 raises ``pyo3_runtime.PanicException``, a
``BaseException`` that passes ``except Exception``. :func:`panic_to_corruption` turns it
into archivey's ``CorruptionError`` with the panic as its cause.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Generator
from types import ModuleType
from typing import Protocol

from archivey.exceptions import (
    CorruptionError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.internal import logs
from archivey.internal.streams.codecs import deps
from archivey.types import OptionalLibrary

MIN_REVISIONS: dict[str, int] = {
    "arm64": 1,
    "crc16_arc": 1,
    "lzw": 1,
    "riscv": 1,
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
def codec_errors(module: ModuleType, kernel: str) -> Generator[None]:
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
    call: after a panic its state may be half updated, so nothing more is asked of
    it. Each wrapper of a stateful kernel object holds one."""

    __slots__ = ("_failure", "_kernel")

    def __init__(self, kernel: str) -> None:
        self._kernel = kernel
        self._failure: CorruptionError | None = None

    @contextlib.contextmanager
    def guard(self) -> Generator[None]:
        """Raise the stored failure, else run the block, storing a panic in it as
        the ``CorruptionError`` it raises."""
        if self._failure is not None:
            raise self._failure
        try:
            with panic_to_corruption(self._kernel):
                yield
        except CorruptionError as exc:
            if caused_by_panic(exc):
                self._failure = exc
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

    __slots__ = ("_decryptor", "_latch")

    def __init__(self, decryptor: _Decryptor) -> None:
        self._decryptor = decryptor
        self._latch = Latch("ZipCrypto")

    def copy(self) -> NativeZipCrypto:
        with self._latch.guard():
            return NativeZipCrypto(self._decryptor.copy())

    def decrypt(self, data: bytes) -> bytes:
        with self._latch.guard():
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


# ── ARM64 and RISC-V branch filters ───────────────────────────────────────────────────


class Branch(Protocol):
    """One stream through a branch filter, as archivey's filter decoder drives it."""

    def decode(self, data: bytes) -> bytes:
        """Return the decoded prefix of everything fed so far. The last few bytes can
        be the start of an instruction that the end of the chunk cut off, so they are
        held back for the next call: at most 3 for ARM64, 7 for RISC-V."""
        ...

    def flush(self) -> bytes:
        """At the end of the input: the bytes held back, unchanged."""
        ...


class _BranchDecoder(Protocol):
    """``archivey_codecs.filters.Arm64Decoder`` or ``RiscvDecoder``."""

    def decode(self, data: bytes) -> bytes: ...

    def flush(self) -> bytes: ...


class NativeBranch:
    """archivey-codecs' ARM64 or RISC-V decoder, as a :class:`Branch`."""

    __slots__ = ("_decoder", "_latch")

    def __init__(self, decoder: _BranchDecoder, kernel: str) -> None:
        self._decoder = decoder
        self._latch = Latch(kernel)

    def decode(self, data: bytes) -> bytes:
        with self._latch.guard():
            return self._decoder.decode(data)

    def flush(self) -> bytes:
        with self._latch.guard():
            return self._decoder.flush()


_BRANCH_CLASSES = {
    "arm64": ("Arm64Decoder", "ARM64"),
    "riscv": ("RiscvDecoder", "RISC-V"),
}


def branch_filter(
    kernel: str, excluded: frozenset[OptionalLibrary], *, isolated: bool
) -> Callable[[int], NativeBranch] | None:
    """A constructor of :class:`NativeBranch` from the filter's start offset, or
    ``None`` to use the Python filter. ``kernel`` is ``"arm64"`` or ``"riscv"``.

    ``isolated`` is ``ProcessIsolation.NATIVE_DECODERS``, which promises that no native
    decoder runs in this process. Until the decoder child can run these kernels, the
    Python filter keeps that promise: it gives the same bytes, only slower.
    """
    if isolated:
        return None
    module = kernels(kernel, excluded)
    if module is None:
        return None
    class_name, label = _BRANCH_CLASSES[kernel]
    decoder = getattr(module.filters, class_name)

    def new(start_offset: int) -> NativeBranch:
        with panic_to_corruption(label):
            return NativeBranch(decoder(start_offset), label)

    return new


# ── Unix compress (LZW) ───────────────────────────────────────────────────────────────


class _LzwDecompressor(Protocol):
    """``archivey_codecs.lzw.Decompressor``."""

    def decompress(self, data: bytes, max_length: int = -1) -> bytes: ...

    def flush(self, max_length: int = -1) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    @property
    def truncation(self) -> str | None: ...

    @property
    def header_params(self) -> tuple[int, bool] | None: ...

    @property
    def nine_bit_widens(self) -> bool | None: ...

    @property
    def clear_offsets(self) -> list[tuple[int, int]]: ...


# Bytes of a ``.Z`` header: the magic and the flags byte.
_LZW_HEADER = 3


class NativeLzw:
    """archivey-codecs' LZW decoder in the shape of the Python ``LzwState``: ``feed``
    and ``flush`` return ``(bytes, units)``, a unit being one CLEAR's segment
    ``(decompressed_size, compressed_size)`` from the CLEAR before it (or from just
    after the header).

    Errors keep the Python decoder's pattern: a bad code hands back the bytes decoded
    before it, and the error raises from the next call.
    """

    __slots__ = ("_at", "_d", "_finished", "_flushed", "_latch", "_module")

    def __init__(
        self, module: ModuleType, decoder: _LzwDecompressor, *, header_in_stream: bool
    ) -> None:
        self._module = module
        self._d = decoder
        self._latch = Latch("LZW")
        self._finished = False
        self._flushed = False
        # The last CLEAR's (input, output) offset: the kernel counts the header in
        # the input when it reads one from the stream, and the units start after it.
        self._at = (_LZW_HEADER if header_in_stream else 0, 0)

    @property
    def header_params(self) -> tuple[int, bool] | None:
        return self._d.header_params

    @property
    def nine_bit_widens(self) -> bool | None:
        return self._d.nine_bit_widens

    @property
    def truncated(self) -> bool:
        return self._d.truncation is not None

    @property
    def truncation(self) -> str | None:
        return self._d.truncation

    def _units(self) -> list[tuple[int, int]]:
        units = []
        comp, decomp = self._at
        for at_in, at_out in self._d.clear_offsets:
            units.append((at_out - decomp, at_in - comp))
            comp, decomp = at_in, at_out
        self._at = (comp, decomp)
        return units

    def _call(self, call: Callable[[], bytes]) -> tuple[bytes, list[tuple[int, int]]]:
        with self._latch.guard(), codec_errors(self._module, "LZW"):
            out = call()
            units = self._units()
        return out, units

    def feed(
        self, data: bytes, max_length: int = -1
    ) -> tuple[bytes, list[tuple[int, int]]]:
        if self._finished:
            return b"", []
        if self._flushed:
            # A flush() that raised: the kernel raises the same error again.
            return self._call(lambda: self._d.flush(max_length))
        return self._call(lambda: self._d.decompress(data, max_length))

    def flush(self) -> tuple[bytes, list[tuple[int, int]]]:
        # A bad code after the output returned here raises from the next call: the
        # kernel keeps the error and raises it again.
        self._flushed = True
        out, units = self._call(self._d.flush)
        self._finished = True
        return out, units

    def is_finished(self) -> bool:
        return self._finished

    @property
    def needs_input(self) -> bool:
        return self._finished or self._d.needs_input


def lzw(
    excluded: frozenset[OptionalLibrary], *, isolated: bool
) -> Callable[..., NativeLzw] | None:
    """A constructor of :class:`NativeLzw` taking ``LzwState``'s keyword arguments,
    or ``None`` to use ``LzwState``. ``isolated`` as for :func:`branch_filter`."""
    if isolated:
        return None
    module = kernels("lzw", excluded)
    if module is None:
        return None
    decompressor = module.lzw.Decompressor

    def new(
        *,
        max_width: int | None = None,
        block_mode: bool | None = None,
        nine_bit_widens: bool | None = None,
    ) -> NativeLzw:
        with codec_errors(module, "LZW"):
            d = decompressor(
                max_width=max_width,
                block_mode=block_mode,
                nine_bit_widens=nine_bit_widens,
            )
        return NativeLzw(module, d, header_in_stream=max_width is None)

    return new
