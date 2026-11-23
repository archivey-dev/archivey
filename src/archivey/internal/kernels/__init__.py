"""archivey's decoding kernels, each with one API whichever decoder runs.

archivey-codecs (the optional Rust package) has fast versions of some of archivey's
Python decoders. Each kernel here is one ``archivey_codecs`` module: a call site asks
for it with the call's excluded libraries and isolation, and gets a namespace with that
module's classes and functions. They are the package's when it is installed, current
and allowed (:mod:`~archivey.internal.kernels._select`), wrapped to raise archivey's
errors (:mod:`~archivey.internal.kernels.rust`), and otherwise the Python twins
(:mod:`~archivey.internal.kernels.python`), which have the same API. The two give the
same bytes and raise the same errors (the package's parity tests compare them), so a
call site does not know which runs: the choice changes speed only. ``library`` is
archivey-codecs when the package decodes, else ``None``, for a call site that records
its backend (LZO does).

Under ``ProcessIsolation.NATIVE_DECODERS`` (``isolated``) a decoding kernel runs in a
decoder child, or as its Python twin when no child can run it; BCJ2 is not run there
yet, so its twin decodes. CRC-16/ARC and ZipCrypto run in this process under every
setting, as checksums and AES do.

Design: openspec change ``rust-codecs-package``, D4 and D5.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, SupportsIndex, overload

from archivey.internal.kernels._select import (
    caused_by_panic,
    decoding_kernels,
    is_panic,
    kernels,
    panic_of,
)
from archivey.types import OptionalLibrary

__all__ = [
    "AppleLz",
    "Bcj2",
    "Bcj2Decompressor",
    "Bcj2Factory",
    "BranchDecoder",
    "BranchFactory",
    "Crc16",
    "Filters",
    "Lzo1x",
    "Lzo1xDecompress",
    "Lzw",
    "LzwDecompressor",
    "LzwFactory",
    "Lzx",
    "LzxDecompressor",
    "LzxFactory",
    "Readable",
    "ZipCrypto",
    "ZipCryptoDecryptor",
    "ZipCryptoFactory",
    "bcj2",
    "caused_by_panic",
    "crc16_arc",
    "filters",
    "is_panic",
    "lzfse",
    "lzo1x",
    "lzvn",
    "lzw",
    "lzx",
    "panic_of",
    "zipcrypto",
]

Buffer = bytes | bytearray | memoryview

_CODECS = OptionalLibrary.ARCHIVEY_CODECS


# ── The API ───────────────────────────────────────────────────────────────────────────


class Crc16(Protocol):
    """``crc16_arc(data, value=0)``: CRC-16/ARC of ``data`` going on from ``value``."""

    def __call__(self, data: Buffer, value: SupportsIndex | None = 0, /) -> int: ...


class Readable(Protocol):
    """An input stream of BCJ2: ``read(n)`` returns at most ``n`` bytes."""

    def read(self, n: int, /) -> Buffer: ...


class ZipCryptoDecryptor(Protocol):
    """``zipcrypto.Decryptor(password)``: the ZipCrypto key state."""

    def decrypt(self, data: Buffer, /) -> bytes: ...

    def copy(self) -> ZipCryptoDecryptor: ...

    @property
    def total_in(self) -> int: ...


class BranchDecoder(Protocol):
    """``filters.Arm64Decoder(start_offset=0)`` or ``RiscvDecoder``: one stream through
    a branch filter. :meth:`decode` returns the decoded prefix of everything fed so far,
    holding back the start of an instruction the chunk cut off (at most 3 bytes for
    ARM64, 7 for RISC-V); :meth:`flush` returns those bytes unchanged."""

    def decode(self, data: Buffer, /) -> bytes: ...

    def flush(self) -> bytes: ...

    @property
    def total_in(self) -> int: ...

    @property
    def total_out(self) -> int: ...


class LzwDecompressor(Protocol):
    """``lzw.Decompressor(*, max_width=None, block_mode=None, nine_bit_widens=None)``:
    Unix ``compress`` with the ``lzma.LZMADecompressor`` interface plus ``flush()``."""

    def decompress(self, data: Buffer, max_length: SupportsIndex = -1) -> bytes: ...

    def flush(self, max_length: SupportsIndex = -1) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    @property
    def unused_data(self) -> bytes: ...

    @property
    def truncation(self) -> str | None: ...

    @property
    def header_params(self) -> tuple[int, bool] | None: ...

    @property
    def nine_bit_widens(self) -> bool | None: ...

    @property
    def clear_offsets(self) -> list[tuple[int, int]]: ...

    @property
    def total_in(self) -> int: ...

    @property
    def total_out(self) -> int: ...


class LzxDecompressor(Protocol):
    """``lzx.Decompressor(window_bits, *, output_size=None)``: one LZX stream (a CAB
    folder), with the ``lzma.LZMADecompressor`` interface plus ``flush()`` and
    ``set_output_size()``. It has no ``unused_data`` or ``total_in``: the stream ends
    at its output size, and the Python decoder reads its input ahead of the output."""

    def set_output_size(self, output_size: SupportsIndex, /) -> None: ...

    def decompress(self, data: Buffer, max_length: SupportsIndex = -1) -> bytes: ...

    def flush(self, max_length: SupportsIndex = -1) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def needs_input(self) -> bool: ...

    @property
    def output_size(self) -> int | None: ...

    @property
    def total_out(self) -> int: ...


class Bcj2Decompressor(Protocol):
    """``bcj2.Decompressor(main, call, jump, rc, *, out_size)``: 7-Zip's BCJ2 over its
    four input streams, read with :meth:`read`."""

    def read(self, max_length: SupportsIndex = -1) -> bytes: ...

    @property
    def eof(self) -> bool: ...

    @property
    def out_size(self) -> int: ...

    @property
    def decoded(self) -> int: ...

    @property
    def total_in(self) -> tuple[int, int, int, int]: ...

    @property
    def total_out(self) -> int: ...


# The constructors, with the package's signatures.


class ZipCryptoFactory(Protocol):
    def __call__(self, password: Buffer) -> ZipCryptoDecryptor: ...


class BranchFactory(Protocol):
    def __call__(self, start_offset: SupportsIndex = 0) -> BranchDecoder: ...


class Lzo1xDecompress(Protocol):
    """Exactly one of ``out_size=`` and ``max_size=``."""

    @overload
    def __call__(self, block: Buffer, /, *, out_size: SupportsIndex) -> bytes: ...

    @overload
    def __call__(self, block: Buffer, /, *, max_size: SupportsIndex) -> bytes: ...

    def __call__(
        self,
        block: Buffer,
        /,
        *,
        out_size: SupportsIndex | None = None,
        max_size: SupportsIndex | None = None,
    ) -> bytes: ...


class LzwFactory(Protocol):
    def __call__(
        self,
        *,
        max_width: SupportsIndex | None = None,
        block_mode: bool | None = None,
        nine_bit_widens: bool | None = None,
    ) -> LzwDecompressor: ...


class LzxFactory(Protocol):
    def __call__(
        self, window_bits: SupportsIndex, *, output_size: SupportsIndex | None = None
    ) -> LzxDecompressor: ...


class Bcj2Factory(Protocol):
    def __call__(
        self,
        main: Readable,
        call: Readable,
        jump: Readable,
        rc: Readable,
        *,
        out_size: SupportsIndex,
    ) -> Bcj2Decompressor: ...


@dataclass(frozen=True, slots=True)
class ZipCrypto:
    """``archivey_codecs.zipcrypto``."""

    Decryptor: ZipCryptoFactory
    library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class Filters:
    """``archivey_codecs.filters``."""

    Arm64Decoder: BranchFactory
    RiscvDecoder: BranchFactory
    # Each filter is its own kernel, so each has its own ``library``.
    arm64_library: OptionalLibrary | None
    riscv_library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class Lzo1x:
    """``archivey_codecs.lzo1x``."""

    decompress: Lzo1xDecompress
    library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class AppleLz:
    """``archivey_codecs.lzfse`` or ``archivey_codecs.lzvn``: a one-shot
    ``decompress`` with ``lzo1x.decompress``'s shape."""

    decompress: Lzo1xDecompress
    library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class Lzw:
    """``archivey_codecs.lzw``."""

    Decompressor: LzwFactory
    library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class Lzx:
    """``archivey_codecs.lzx``."""

    Decompressor: LzxFactory
    library: OptionalLibrary | None


@dataclass(frozen=True, slots=True)
class Bcj2:
    """``archivey_codecs.bcj2``."""

    Decompressor: Bcj2Factory
    library: OptionalLibrary | None


# ── The switch ────────────────────────────────────────────────────────────────────────


def _bind(cls: Callable[..., Any], module: object) -> Any:
    """``cls`` with the package module (or its stand-in) as its first argument. Its
    signature, for the reader and ``inspect``, is the rest of ``cls``'s: the
    namespace field's type gives it to the type checker."""
    return functools.partial(cls, module)


def crc16_arc(excluded: frozenset[OptionalLibrary]) -> Crc16:
    """``crc16_arc``: the package's when it is installed and ``excluded`` leaves it
    on, else the Python one. Both give the same value."""
    module = kernels("crc16_arc", excluded)
    if module is None:
        from archivey.internal.kernels import python

        return python.crc16_arc
    from archivey.internal.kernels import rust

    return rust.crc16_arc(module)


def zipcrypto(excluded: frozenset[OptionalLibrary]) -> ZipCrypto:
    """``zipcrypto``, in this process under every isolation setting."""
    module = kernels("zipcrypto", excluded)
    if module is None:
        from archivey.internal.kernels.python import zipcrypto as twin

        return ZipCrypto(Decryptor=twin.Decryptor, library=None)
    from archivey.internal.kernels import rust

    return ZipCrypto(Decryptor=_bind(rust.ZipCryptoDecryptor, module), library=_CODECS)


def filters(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> Filters:
    """``filters`` (ARM64 and RISC-V). The two filters are separate kernels, so each
    is the package's or the twin as its own revision allows."""
    from archivey.internal.kernels import rust
    from archivey.internal.kernels.python import filters as twin

    arm64 = decoding_kernels("arm64", excluded, isolated=isolated)
    riscv = decoding_kernels("riscv", excluded, isolated=isolated)
    return Filters(
        Arm64Decoder=twin.Arm64Decoder
        if arm64 is None
        else _bind(rust.Arm64Decoder, arm64),
        RiscvDecoder=twin.RiscvDecoder
        if riscv is None
        else _bind(rust.RiscvDecoder, riscv),
        arm64_library=None if arm64 is None else _CODECS,
        riscv_library=None if riscv is None else _CODECS,
    )


def lzo1x(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> Lzo1x:
    """``lzo1x``. Under ``isolated`` each block decodes in a decoder child. LZO's call
    site takes only the package from here: compress-utils comes between it and the
    Python decoder (design question 11), which the call site calls directly."""
    module = decoding_kernels("lzo1x", excluded, isolated=isolated)
    if module is None:
        from archivey.internal.kernels.python import lzo1x as twin

        return Lzo1x(decompress=twin.decompress, library=None)
    from archivey.internal.kernels import rust

    return Lzo1x(decompress=rust.lzo1x_decompress(module), library=_CODECS)


def lzw(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> Lzw:
    """``lzw`` (Unix ``compress``)."""
    module = decoding_kernels("lzw", excluded, isolated=isolated)
    if module is None:
        from archivey.internal.kernels.python import lzw as twin

        return Lzw(Decompressor=twin.Decompressor, library=None)
    from archivey.internal.kernels import rust

    return Lzw(Decompressor=_bind(rust.LzwDecompressor, module), library=_CODECS)


def lzx(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> Lzx:
    """``lzx`` (CAB's LZX)."""
    module = decoding_kernels("lzx", excluded, isolated=isolated)
    if module is None:
        from archivey.internal.kernels.python import lzx as twin

        return Lzx(Decompressor=twin.Decompressor, library=None)
    from archivey.internal.kernels import rust

    return Lzx(Decompressor=_bind(rust.LzxDecompressor, module), library=_CODECS)


def bcj2(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> Bcj2:
    """``bcj2`` (7-Zip's four-stream x86 filter). Under ``isolated`` the twin
    decodes, until the decoder child can carry BCJ2's four inputs."""
    module = None if isolated else kernels("bcj2", excluded)
    if module is None:
        from archivey.internal.kernels.python import bcj2 as twin

        return Bcj2(Decompressor=twin.Decompressor, library=None)
    from archivey.internal.kernels import rust

    return Bcj2(Decompressor=_bind(rust.Bcj2Decompressor, module), library=_CODECS)


def lzfse(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> AppleLz:
    """``lzfse`` (Apple's LZFSE, in DMG runs). Under ``isolated`` the twin decodes,
    until the decoder child can run it."""
    return _apple_lz("lzfse", excluded, isolated=isolated)


def lzvn(excluded: frozenset[OptionalLibrary], *, isolated: bool) -> AppleLz:
    """``lzvn`` (raw LZVN, in HFS+ compressed files). Under ``isolated`` the twin
    decodes, until the decoder child can run it."""
    return _apple_lz("lzvn", excluded, isolated=isolated)


def _apple_lz(
    kernel: Literal["lzfse", "lzvn"],
    excluded: frozenset[OptionalLibrary],
    *,
    isolated: bool,
) -> AppleLz:
    module = None if isolated else kernels(kernel, excluded)
    if module is None:
        from archivey.internal.kernels.python import (
            lzfse as lzfse_twin,
            lzvn as lzvn_twin,
        )

        twin = lzfse_twin if kernel == "lzfse" else lzvn_twin
        return AppleLz(decompress=twin.decompress, library=None)
    from archivey.internal.kernels import rust

    return AppleLz(decompress=rust.apple_lz_decompress(module, kernel), library=_CODECS)
