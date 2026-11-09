"""The optional Rust kernels (the ``archivey-native`` package), and the one place that
decides whether to use them.

``archivey-native`` holds Rust ports of decoders archivey otherwise runs in Python. It
is an accelerator in the DR-5 sense: with it or without it, a read returns the same
bytes and raises the same exception type with the same message. The pure-Python code
stays the reference, and ``packages/archivey-native/tests`` checks each kernel against
it on clean, damaged and random input.

Three things turn the kernels off, each falling back to the Python decoder:

- the package is absent, fails to import, or reports an ``ABI_VERSION`` this archivey
  does not know (logged once);
- ``OptionalLibrary.ARCHIVEY_NATIVE`` is in the caller's ``excluded`` set, where the
  call site has one;
- the environment variable ``ARCHIVEY_NATIVE=0`` (for bisecting a difference).

The kernels report two exception types of their own, ``CorruptData`` and
``TruncatedData``; the wrappers here turn them into what the Python decoder raises.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from types import ModuleType
from typing import Any, Protocol

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal import logs
from archivey.internal.streams.codecs import deps
from archivey.types import OptionalLibrary

#: The kernel ABI this archivey speaks. A package with another one is not used.
NATIVE_ABI = 1

_abi_warned = False


def kernels(excluded: frozenset[OptionalLibrary] = frozenset()) -> ModuleType | None:
    """The native module when it may be used, else ``None``."""
    global _abi_warned
    if OptionalLibrary.ARCHIVEY_NATIVE in excluded:
        return None
    if os.environ.get("ARCHIVEY_NATIVE") == "0":
        return None
    module = deps.native.load()
    if module is None:
        return None
    if getattr(module, "ABI_VERSION", None) != NATIVE_ABI:
        if not _abi_warned:
            _abi_warned = True
            logs.streams.warning(
                "archivey-native has kernel ABI %r, this archivey needs %r; decoding "
                "in Python instead.",
                getattr(module, "ABI_VERSION", None),
                NATIVE_ABI,
            )
        return None
    return module


# ── LZO1X ──────────────────────────────────────────────────────────────────────────


def lzo1x(
    excluded: frozenset[OptionalLibrary], error: type[ValueError]
) -> Callable[[bytes, int], bytes] | None:
    """The native LZO1X block decoder raising ``error``, or ``None``."""
    native = kernels(excluded)
    if native is None:
        return None
    decompress, corrupt = native.lzo1x_decompress, native.CorruptData

    def decode(data: bytes, limit: int) -> bytes:
        try:
            return decompress(data, limit)
        except corrupt as exc:
            raise error(str(exc)) from None

    return decode


# ── Branch filters ─────────────────────────────────────────────────────────────────


def branch_filter(
    name: str, excluded: frozenset[OptionalLibrary] = frozenset()
) -> Callable[[bytes, int], bytes] | None:
    """The native ``arm64_decode`` or ``riscv_decode``, or ``None``. They cannot fail."""
    native = kernels(excluded)
    return None if native is None else getattr(native, name)


# ── ZipCrypto ──────────────────────────────────────────────────────────────────────


class ZipCryptoState(Protocol):
    k0: int
    k1: int
    k2: int

    def decrypt(self, data: bytes) -> bytes: ...
    def copy(self) -> ZipCryptoState: ...


def zipcrypto_keys(
    password: bytes, excluded: frozenset[OptionalLibrary] = frozenset()
) -> ZipCryptoState | None:
    native = kernels(excluded)
    return None if native is None else native.ZipCryptoKeys(password)


# ── LZX ────────────────────────────────────────────────────────────────────────────


class FrameDecoder(Protocol):
    def decode_frame(self, frame_size: int) -> bytes: ...


class _NativeLzx:
    __slots__ = ("_corrupt", "_decoder", "_truncated")

    def __init__(self, native: ModuleType, decoder: Any) -> None:
        self._decoder = decoder
        self._corrupt = native.CorruptData
        self._truncated = native.TruncatedData

    def decode_frame(self, frame_size: int) -> bytes:
        try:
            return self._decoder.decode_frame(frame_size)
        except self._truncated as exc:
            raise TruncatedError(str(exc)) from None
        except self._corrupt as exc:
            raise CorruptionError(str(exc)) from None


def lzx_decoder(
    window_bits: int,
    more: Callable[[], bytes | None],
    excluded: frozenset[OptionalLibrary] = frozenset(),
) -> FrameDecoder | None:
    """A native LZX decoder, or ``None``. Exceptions ``more`` raises pass through."""
    native = kernels(excluded)
    if native is None:
        return None
    try:
        decoder = native.LzxDecoder(window_bits, more)
    except native.CorruptData as exc:
        raise CorruptionError(str(exc)) from None
    return _NativeLzx(native, decoder)


# ── Unix compress (.Z) LZW ─────────────────────────────────────────────────────────


class LzwEngine(Protocol):
    """What ``UnixCompressDecoder`` needs of an LZW state: ``LzwState`` or the native one."""

    def feed(
        self, data: bytes, max_length: int = -1
    ) -> tuple[bytes, list[tuple[int, int]]]: ...
    def flush(self) -> tuple[bytes, list[tuple[int, int]]]: ...
    def is_finished(self) -> bool: ...
    @property
    def needs_input(self) -> bool: ...
    @property
    def header_params(self) -> tuple[int, bool] | None: ...
    @property
    def nine_bit_widens(self) -> bool | None: ...
    @property
    def truncation(self) -> str | None: ...


class _NativeLzw:
    """archivey-native's ``LzwState`` behind ``LzwState``'s interface and exceptions."""

    __slots__ = ("_errors", "_state")

    def __init__(self, native: ModuleType, state: Any) -> None:
        self._state = state
        self._errors = (
            native.TruncatedData,
            native.CorruptData,
            native.UnsupportedData,
        )

    def _call(self, fn: Callable[[], tuple[bytes, list[tuple[int, int]]]]):
        truncated, corrupt, unsupported = self._errors
        try:
            return fn()
        except truncated as exc:
            raise TruncatedError(str(exc)) from None
        except corrupt as exc:
            raise CorruptionError(str(exc)) from None
        except unsupported as exc:
            from archivey.exceptions import UnsupportedFeatureError

            raise UnsupportedFeatureError(str(exc)) from None

    def feed(
        self, data: bytes, max_length: int = -1
    ) -> tuple[bytes, list[tuple[int, int]]]:
        return self._call(lambda: self._state.feed(data, max_length))

    def flush(self) -> tuple[bytes, list[tuple[int, int]]]:
        return self._call(self._state.flush)

    def is_finished(self) -> bool:
        return self._state.is_finished()

    @property
    def needs_input(self) -> bool:
        return self._state.needs_input

    @property
    def header_params(self) -> tuple[int, bool] | None:
        return self._state.header_params

    @property
    def nine_bit_widens(self) -> bool | None:
        return self._state.nine_bit_widens

    @property
    def truncated(self) -> bool:
        return self._state.truncated

    @property
    def truncation(self) -> str | None:
        return self._state.truncation


def lzw_state(
    *,
    max_width: int | None = None,
    block_mode: bool | None = None,
    nine_bit_widens: bool | None = None,
    excluded: frozenset[OptionalLibrary] = frozenset(),
) -> _NativeLzw | None:
    native = kernels(excluded)
    if native is None:
        return None
    state = native.LzwState(
        max_width=max_width, block_mode=block_mode, nine_bit_widens=nine_bit_widens
    )
    return _NativeLzw(native, state)


# ── BCJ2 ───────────────────────────────────────────────────────────────────────────


class NativeBcj2:
    """archivey-native's BCJ2 decode loop for ``Bcj2DecoderStream``."""

    __slots__ = ("_core", "_corrupt", "_truncated")

    def __init__(self, native: ModuleType, core: Any) -> None:
        self._core = core
        self._corrupt = native.CorruptData
        self._truncated = native.TruncatedData

    def decode_block(self, left: int, pending: bytearray) -> int:
        """Append the next block's output to ``pending``; return how many bytes. On an
        error, what decoded before it is appended first, as the Python loop does."""
        try:
            data = self._core.decode_block(left)
        except (self._truncated, self._corrupt) as exc:
            partial = self._core.take_partial()
            pending += partial
            error = (
                TruncatedError if isinstance(exc, self._truncated) else CorruptionError
            )
            raise _with_count(error(str(exc)), len(partial)) from None
        pending += data
        return len(data)

    def check_inputs_finished(self) -> None:
        try:
            self._core.check_inputs_finished()
        except self._corrupt as exc:
            raise CorruptionError(str(exc)) from None


def _with_count(exc: Exception, count: int) -> Exception:
    setattr(exc, "decoded_before", count)  # noqa: B010 - an ad hoc attribute
    return exc


def bcj2_core(
    reads: tuple[Callable[[int], bytes], ...],
    excluded: frozenset[OptionalLibrary] = frozenset(),
) -> NativeBcj2 | None:
    """A native BCJ2 loop over the four streams' ``read`` methods, or ``None``."""
    native = kernels(excluded)
    if native is None:
        return None
    return NativeBcj2(native, native.Bcj2Core(*reads))
