"""archivey-codecs' kernel objects with archivey's errors.

Each class here wraps one object of the package (or its stand-in in a decoder child,
:mod:`archivey.internal.kernels.child`) and keeps its API. A method raises the
package's errors as archivey's with the same message (``CorruptDataError`` as
``CorruptionError``, ``TruncatedDataError`` as ``TruncatedError``,
``UnsupportedDataError`` as ``UnsupportedFeatureError``), and a Rust panic as
``CorruptionError`` with the panic as its cause. After a panic the object refuses every
later method call, and its counters still read
(:class:`~archivey.internal.kernels._select.Latch`). So an object here and its Python
twin in :mod:`archivey.internal.kernels.python` raise the same errors.
"""

from __future__ import annotations

from collections.abc import Callable
from types import ModuleType
from typing import Any, TypeVar

from archivey.internal.kernels._select import (
    Kernels,
    Latch,
    codec_errors,
    panic_to_corruption,
)

_T = TypeVar("_T")


class _Guarded:
    """One package object: its calls go through :meth:`_run`. CRC-16, ZipCrypto and
    BCJ2 run in this process only, so they take the package module itself."""

    __slots__ = ("_k", "_latch", "_module")

    _label = ""

    def __init__(self, module: Kernels, make: Callable[[], Any]) -> None:
        self._module = module
        self._latch = Latch(self._label)
        with codec_errors(module, self._label):
            self._k = make()

    def _run(self, call: Callable[[], _T]) -> _T:
        with self._latch.guard(), codec_errors(self._module, self._label):
            return call()

    def close(self) -> None:
        """Give back the decoder child the object holds, if it is in one."""
        close = getattr(self._k, "close", None)
        if close is not None:
            close()


# ── CRC-16/ARC ────────────────────────────────────────────────────────────────────────


def crc16_arc(
    module: ModuleType,
) -> Callable[[bytes | bytearray | memoryview, int], int]:
    """The package's ``crc16_arc(data, value=0)``."""
    kernel = module.crc16_arc

    def crc16(data: bytes | bytearray | memoryview, value: int = 0, /) -> int:
        with panic_to_corruption("CRC-16"):
            return kernel(data, value)

    return crc16


# ── ZipCrypto ─────────────────────────────────────────────────────────────────────────


class ZipCryptoDecryptor(_Guarded):
    """``zipcrypto.Decryptor``."""

    __slots__ = ()
    _label = "ZipCrypto"

    def __init__(self, module: ModuleType, password: bytes) -> None:
        super().__init__(module, lambda: module.zipcrypto.Decryptor(password))

    @classmethod
    def _of(cls, module: Kernels, kernel: Any) -> ZipCryptoDecryptor:
        self = cls.__new__(cls)
        self._module = module
        self._latch = Latch(cls._label)
        self._k = kernel
        return self

    def decrypt(self, data: bytes | bytearray | memoryview) -> bytes:
        return self._run(lambda: self._k.decrypt(data))

    def copy(self) -> ZipCryptoDecryptor:
        return ZipCryptoDecryptor._of(self._module, self._run(self._k.copy))

    @property
    def total_in(self) -> int:
        return self._k.total_in


# ── ARM64 and RISC-V branch filters ───────────────────────────────────────────────────


class BranchDecoder(_Guarded):
    """``filters.Arm64Decoder`` or ``RiscvDecoder``."""

    __slots__ = ()

    # Its kernel object may be in a decoder child (``release_decoder``).
    holds_decoder_child = True

    def decode(self, data: bytes | bytearray | memoryview) -> bytes:
        return self._run(lambda: self._k.decode(data))

    def flush(self) -> bytes:
        return self._run(self._k.flush)

    @property
    def total_in(self) -> int:
        return self._k.total_in

    @property
    def total_out(self) -> int:
        return self._k.total_out


class Arm64Decoder(BranchDecoder):
    __slots__ = ()
    _label = "ARM64"

    def __init__(self, module: Kernels, start_offset: int = 0) -> None:
        super().__init__(module, lambda: module.filters.Arm64Decoder(start_offset))


class RiscvDecoder(BranchDecoder):
    __slots__ = ()
    _label = "RISC-V"

    def __init__(self, module: Kernels, start_offset: int = 0) -> None:
        super().__init__(module, lambda: module.filters.RiscvDecoder(start_offset))


# ── LZO1X ─────────────────────────────────────────────────────────────────────────────


def lzo1x_decompress(module: Kernels) -> Callable[..., bytes]:
    """The package's ``lzo1x.decompress(block, *, out_size= | max_size=)``."""
    kernel = module.lzo1x.decompress

    def decompress(
        block: bytes | bytearray | memoryview,
        /,
        *,
        out_size: int | None = None,
        max_size: int | None = None,
    ) -> bytes:
        # Checked here, as the twin does: the child's proxy passes only one of them on.
        if (out_size is None) == (max_size is None):
            raise TypeError(
                "lzo1x.decompress() takes exactly one of out_size= and max_size="
            )
        with codec_errors(module, "LZO1X"):
            if out_size is not None:
                return kernel(block, out_size=out_size)
            return kernel(block, max_size=max_size)

    return decompress


# ── Unix compress (LZW) ───────────────────────────────────────────────────────────────


class LzwDecompressor(_Guarded):
    """``lzw.Decompressor``."""

    __slots__ = ()
    _label = "LZW"

    # Its kernel object may be in a decoder child (``release_decoder``).
    holds_decoder_child = True

    def __init__(
        self,
        module: Kernels,
        *,
        max_width: int | None = None,
        block_mode: bool | None = None,
        nine_bit_widens: bool | None = None,
    ) -> None:
        super().__init__(
            module,
            lambda: module.lzw.Decompressor(
                max_width=max_width,
                block_mode=block_mode,
                nine_bit_widens=nine_bit_widens,
            ),
        )

    def decompress(
        self, data: bytes | bytearray | memoryview, max_length: int = -1
    ) -> bytes:
        return self._run(lambda: self._k.decompress(data, max_length))

    def flush(self, max_length: int = -1) -> bytes:
        return self._run(lambda: self._k.flush(max_length))

    @property
    def eof(self) -> bool:
        return self._k.eof

    @property
    def needs_input(self) -> bool:
        return self._k.needs_input

    @property
    def unused_data(self) -> bytes:
        return self._k.unused_data

    @property
    def truncation(self) -> str | None:
        return self._k.truncation

    @property
    def header_params(self) -> tuple[int, bool] | None:
        return self._k.header_params

    @property
    def nine_bit_widens(self) -> bool | None:
        return self._k.nine_bit_widens

    @property
    def clear_offsets(self) -> list[tuple[int, int]]:
        return self._k.clear_offsets

    @property
    def total_in(self) -> int:
        return self._k.total_in

    @property
    def total_out(self) -> int:
        return self._k.total_out


# ── LZX ───────────────────────────────────────────────────────────────────────────────


class LzxDecompressor(_Guarded):
    """``lzx.Decompressor``."""

    __slots__ = ()
    _label = "LZX"

    # Its kernel object may be in a decoder child (``release_decoder``).
    holds_decoder_child = True

    def __init__(
        self, module: Kernels, window_bits: int, *, output_size: int | None = None
    ) -> None:
        super().__init__(
            module,
            lambda: module.lzx.Decompressor(window_bits, output_size=output_size),
        )

    def set_output_size(self, output_size: int) -> None:
        self._run(lambda: self._k.set_output_size(output_size))

    def decompress(
        self, data: bytes | bytearray | memoryview, max_length: int = -1
    ) -> bytes:
        return self._run(lambda: self._k.decompress(data, max_length))

    def flush(self, max_length: int = -1) -> bytes:
        return self._run(lambda: self._k.flush(max_length))

    @property
    def eof(self) -> bool:
        return self._k.eof

    @property
    def needs_input(self) -> bool:
        return self._k.needs_input

    @property
    def output_size(self) -> int | None:
        return self._k.output_size

    @property
    def total_out(self) -> int:
        return self._k.total_out


# ── BCJ2 ──────────────────────────────────────────────────────────────────────────────


class Bcj2Decompressor(_Guarded):
    """``bcj2.Decompressor``."""

    __slots__ = ()
    _label = "BCJ2"

    def __init__(
        self,
        module: ModuleType,
        main: Any,
        call: Any,
        jump: Any,
        rc: Any,
        *,
        out_size: int,
    ) -> None:
        super().__init__(
            module,
            lambda: module.bcj2.Decompressor(main, call, jump, rc, out_size=out_size),
        )

    def read(self, max_length: int = -1) -> bytes:
        return self._run(lambda: self._k.read(max_length))

    @property
    def eof(self) -> bool:
        return self._k.eof

    @property
    def out_size(self) -> int:
        return self._k.out_size

    @property
    def decoded(self) -> int:
        return self._k.decoded

    @property
    def total_in(self) -> tuple[int, int, int, int]:
        return self._k.total_in

    @property
    def total_out(self) -> int:
        return self._k.total_out
